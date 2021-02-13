//! Transcodes videos stored in Moodle to more common formats. It especially
//! targets converting MOV so students don't require QuickTime.

// Copyright 2021 Sheldon Young <sheldon@softdev.ca>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bb8::Pool;
use bb8_postgres::PostgresConnectionManager;
use clap::{app_from_crate, crate_authors, crate_description, crate_name, crate_version, Arg};
use core::fmt::Write;
use log::{debug, error, trace, LevelFilter};
use sha1::{Digest, Sha1};
use simplelog::*;
use std::{
    collections::{HashMap, HashSet},
    fs,
    fs::File,
    io,
    io::Error,
    io::ErrorKind,
    path::{Path, PathBuf},
    process::Command,
    time::Instant,
};
use std::{
    process::ExitStatus,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::time::{self, Duration};
use tokio_postgres::NoTls;
use uuid::Uuid;

const LOG_LEVEL: LevelFilter = LevelFilter::Trace;

const DEFAULT_DATADIR: &str = "/srv/moodle/data";
const DEFAULT_DB_HOST: &str = "localhost";
const DEFAULT_DB_NAME: &str = "moodle";
const DEFAULT_DB_PORT: &str = "5432";
const DEFAULT_DB_PREFIX: &str = "mdl_";
const DEFAULT_DB_USER: &str = "moodleuser";
const DEFAULT_DELAY_SECONDS: u32 = 60;
const DEFAULT_VERBOSITY: u64 = 1;

#[derive(Debug)]
struct Conversion {
    source_content_type: String,
    source_extension: String,
    dest_content_type: String,
    dest_extension: String, // Also the ffmpeg format name
}

/// Matches the schema of the files table.
#[derive(Clone, Debug)]
struct FileRow {
    id: i64,
    contenthash: String,
    pathnamehash: String,
    contextid: i64,
    component: String,
    filearea: String,
    itemid: i64,
    filepath: String,

    /// The filename the user selected, can be anything.
    filename: String,

    userid: Option<i64>,
    filesize: i64,
    mimetype: String,
    status: i64,

    /// The filename as it was uploaded or other historical origin.
    source: Option<String>,

    author: Option<String>,
    license: Option<String>,
    sortorder: i64,

    /// Set to reflect the ID of the newly inserted row for the transcoded version.
    referencefileid: Option<i64>,
}

impl FileRow {
    /// There is no guarantee the transcoded file still exists.
    fn has_been_transcoded(&self) -> bool {
        self.referencefileid.is_some()
    }

    /// Matches `get_pathname_hash` in the Moodle 3.10 source.
    fn pathnamehash(&self) -> String {
        let to_hash = format!(
            "/{}/{}/{}/{}{}{}",
            self.contextid,
            self.component,
            self.filearea,
            self.itemid,
            self.filepath,
            self.filename
        );
        let digest = Sha1::digest(to_hash.as_bytes());
        to_hex_string(digest.as_ref())
    }
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    // What to convert.
    let conversions = [
        // Audio
        Conversion {
            source_content_type: "audio/ogg".to_string(),
            source_extension: "ogg".to_string(),
            dest_content_type: "audio/mp4".to_string(),
            dest_extension: "mp4".to_string(),
        },
        // Video
        Conversion {
            source_content_type: "video/quicktime".to_string(),
            source_extension: "mov".to_string(),
            dest_content_type: "video/mp4".to_string(),
            dest_extension: "mp4".to_string(),
        },
    ];
    let convert_content_types: HashSet<&String> =
        conversions.iter().map(|c| &c.source_content_type).collect();

    // Setup logging.
    let log_config = ConfigBuilder::new()
        .set_time_level(LevelFilter::Off)
        .set_thread_level(LevelFilter::Off)
        .set_target_level(LOG_LEVEL)
        .add_filter_allow_str(crate_name!()) // tokio has a lot of logging to hide
        .build();
    TermLogger::init(LOG_LEVEL, log_config.clone(), TerminalMode::Mixed).unwrap();

    // Parse the command line.
    let default_delay_str = &DEFAULT_DELAY_SECONDS.to_string();
    let cli_matches = app_from_crate!()
        .arg(
            Arg::with_name("datadir")
                .long("datadir")
                .takes_value(true)
                .default_value(DEFAULT_DATADIR)
                .help("Location of the Moodle data directory"),
        )
        .arg(
            Arg::with_name("dbhost")
                .long("dbhost")
                .takes_value(true)
                .default_value(DEFAULT_DB_HOST)
                .help("Database server hostname"),
        )
        .arg(
            Arg::with_name("dbport")
                .long("dbport")
                .takes_value(true)
                .default_value(DEFAULT_DB_PORT)
                .help("Database server port number"),
        )
        .arg(
            Arg::with_name("dbname")
                .long("dbname")
                .takes_value(true)
                .default_value(DEFAULT_DB_NAME)
                .help("Database name"),
        )
        .arg(
            Arg::with_name("dbuser")
                .long("dbuser")
                .takes_value(true)
                .default_value(DEFAULT_DB_USER)
                .help("Database username"),
        )
        .arg(
            Arg::with_name("dbpass")
                .takes_value(true)
                .long("dbpass")
                .help("Database password"),
        )
        .arg(
            Arg::with_name("dbprefix")
                .long("dbprefix")
                .takes_value(true)
                .default_value(DEFAULT_DB_PREFIX)
                .help("Table name prefix"),
        )
        .arg(
            Arg::with_name("quiet")
                .short("q")
                .help("Messages are shown only when they are important"),
        )
        .arg(
            Arg::with_name("repeat")
                .long("repeat")
                .short("r")
                .default_value(default_delay_str)
                .takes_value(true)
                .help("Continously poll for new files with this many seconds between"),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .multiple(true)
                .help("Explain what is being done, can be specified multiple times"),
        )
        .get_matches();

    let filedir_path = Path::new(cli_matches.value_of("datadir").unwrap()).join("filedir");

    let run_once = cli_matches.value_of("repeat").is_none();
    let delay = match cli_matches.value_of("repeat") {
        None => DEFAULT_DELAY_SECONDS,
        Some(str) => match str.parse::<u32>() {
            Ok(delay) => delay,
            Err(_) => {
                eprintln!("Delay in seconds must be numeric");
                return Err(std::io::Error::new(
                    ErrorKind::InvalidInput,
                    "Delay in seconds must be numeric",
                ));
            }
        },
    };

    let db_name = cli_matches.value_of("dbname").unwrap();
    let db_host = cli_matches.value_of("dbhost").unwrap();
    let db_prefix = cli_matches.value_of("dbprefix").unwrap();
    let db_user_opt = cli_matches.value_of("dbuser");
    let db_pass_opt = cli_matches.value_of("dbpass");
    let db_port = match cli_matches.value_of("dbport").unwrap().parse::<u16>() {
        Ok(port) => port,
        Err(_) => {
            eprintln!("Database port number must be numeric");
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                "Database port number must be numeric",
            ));
        }
    };

    let verbosity = DEFAULT_VERBOSITY + cli_matches.occurrences_of("verbose")
        - cli_matches.occurrences_of("quiet");

    // Database connection configuration.
    let mut db_config_init = tokio_postgres::config::Config::new();
    let mut db_config = db_config_init
        .application_name(crate_name!())
        .dbname(db_name)
        .host(db_host)
        .port(db_port);
    if let Some(db_user) = db_user_opt {
        db_config = db_config.user(db_user);
    }
    if let Some(db_pass) = db_pass_opt {
        db_config = db_config.password(db_pass);
    }

    let db_manager = PostgresConnectionManager::new(db_config.clone(), NoTls);
    let db_pool = match Pool::builder().build(db_manager).await {
        Ok(pool) => pool,
        Err(e) => panic!("Database connection pool error: {:?}", e),
    };

    // Look for files to process then delay and try again.s
    loop {
        let connection;
        match db_pool.get().await {
            Ok(con) => connection = con,
            Err(error) => {
                error!("Database connection error: {}", error);
                debug!(
                    "Database configuration is host={}, port={}, user={}, password={}",
                    db_host,
                    db_port,
                    db_user_opt.unwrap_or("<none>"),
                    db_pass_opt
                        .map(|pass| "*".repeat(pass.len()))
                        .unwrap_or("<none>".to_string())
                );
                continue;
            }
        }

        // TODO: Can optimize by not redoing the processing there is nothing new.  Can
        // check the highest ID to see if it's higher than thelast go-around.
        let filerows_sql = format!(
            "select * from {}files where mimetype is not null order by id desc",
            db_prefix
        ); // Newest first
        let filerows: Vec<FileRow> = match connection.query(filerows_sql.as_str(), &[]).await {
            Err(error) => {
                error!("Database error during: {}", error);
                return Err(Error::new(ErrorKind::Other, error));
            }
            Ok(rows) => rows
                .iter()
                .map(|row| FileRow {
                    id: row.get("id"),
                    contenthash: row.get("contenthash"),
                    pathnamehash: row.get("pathnamehash"),
                    contextid: row.get("contextid"),
                    component: row.get("component"),
                    filearea: row.get("filearea"),
                    itemid: row.get("itemid"),
                    filepath: row.get("filepath"),
                    filename: row.get("filename"),
                    userid: row.get("userid"),
                    filesize: row.get("filesize"),
                    mimetype: row.get("mimetype"),
                    status: row.get("status"),
                    source: row.get("source"),
                    author: row.get("author"),
                    license: row.get("license"),
                    sortorder: row.get("sortorder"),
                    referencefileid: row.get("referencefileid"),
                })
                .collect(),
        };

        let filerows_by_id: HashMap<i64, &FileRow> =
            filerows.iter().map(|row| (row.id, row)).collect();

        // Files that have been transcoded and still exist.
        let filerows_transcodes: Vec<&FileRow> = filerows
            .iter()
            .filter(|row| {
                row.has_been_transcoded()
                    && filerows_by_id.contains_key(&row.referencefileid.unwrap())
            })
            .collect();

        // Start with one of each content hash to avoid having to keep a record of what was
        // already transcribed this time through.
        let filerows_maybe_convert: HashMap<String, &FileRow> = filerows
            .iter()
            .filter_map(|row| {
                let include =
                    !row.has_been_transcoded() && convert_content_types.contains(&row.mimetype);
                include.then(|| (row.contenthash.clone(), row))
            })
            .collect();
        debug!(
            "Found {} candidates to transcode",
            filerows_maybe_convert.len()
        );
        for &filerow in filerows_maybe_convert.values() {
            let dest_content_hash;
            let dest_content_type;
            let dest_filesize;
            let dest_extension;

            if let Some(already_converted) = filerows_transcodes
                .iter()
                .find(|row| row.id != filerow.id && row.contenthash == filerow.contenthash)
            {
                // Reuse an existing transcode if one already exists for another item.
                let existing_transcode_row =
                    filerows_by_id[&already_converted.referencefileid.unwrap()];
                trace!(
                    "Found an existing row with same hash: {:?}",
                    existing_transcode_row
                );
                dest_content_hash = existing_transcode_row.contenthash.clone();
                dest_content_type = existing_transcode_row.mimetype.clone();
                dest_filesize = existing_transcode_row.filesize;
                dest_extension = Path::new(&existing_transcode_row.filename)
                    .extension()
                    .map(|t| t.to_string_lossy().to_string())
                    .unwrap_or("bin".to_string());
            } else {
                // Transcode the file.
                let conversion = conversions
                    .iter()
                    .find(|conv| conv.source_content_type == filerow.mimetype)
                    .unwrap();

                dest_extension = conversion.dest_extension.clone();
                dest_content_type = conversion.dest_content_type.clone();
                if verbosity > 1 {
                    println!(
                        "Transcoding {} from {} to {} ({})",
                        filerow.filename,
                        filerow.mimetype,
                        conversion.dest_content_type,
                        conversion.dest_extension
                    );
                } else if verbosity > 0 {
                    println!("Transcoding {}", filerow.filename);
                }

                // Temporary file that cannot be guessed.
                let temp_filename =
                    format!("{}-{}.{}", crate_name!(), Uuid::new_v4(), dest_extension);
                let temp_path = std::env::temp_dir().join(&temp_filename);
                trace!("Temporary file is {:?}", temp_path);

                let start_time = Instant::now();

                // If a conversion fails then convert the remaining files anyway.
                match filerow.convert(conversion, &filedir_path, &temp_path) {
                    Ok(status) if status.success() => {
                        trace!("Conversion completed normally");
                    }
                    Ok(status) => {
                        error!("Transcoder terminated {:?}", status);
                        continue;
                    }
                    Err(error) => {
                        error!("{}", error);
                        continue;
                    }
                }
                if verbosity > 1 {
                    println!(
                        "Transcoding took {:?}",
                        Instant::now().duration_since(start_time)
                    );
                }

                // Calculate the data directory filename from the hash of the file contents.
                let mut temp_file = File::open(&temp_path).expect("opening temporary file");
                let mut hasher = Sha1::new();
                dest_filesize =
                    io::copy(&mut temp_file, &mut hasher).expect("hashing temporary file") as i64;
                dest_content_hash = to_hex_string(hasher.finalize().as_ref());
                let dest_path = hashed_path(&filedir_path, dest_content_hash.as_str());

                // Create the destination directories if required.
                let data_path = dest_path.parent().expect("destination file has a parent");
                fs::create_dir_all(data_path).expect("create destination directories");

                // Try a simple rename first and if that fails, such as when the move is across
                // filesystems, revert to a basic copy and delete.
                if let Err(_) = fs::rename(&temp_path, &dest_path) {
                    trace!("\tmoving by copying");
                    io::copy(
                        &mut temp_file,
                        &mut File::open(&dest_path).expect("opening destination file"),
                    )
                    .expect("copying to destination");
                    // TODO: Remove the temporary file even if the copy fails.
                    fs::remove_file(temp_path).expect("removing temporary file");
                }
            }

            // Add an "mtr###-" to the start of the filename so it doesn't conflict with
            // an existing file and create an identicial pathnamehash.
            let dest_filename = format!(
                "mtr-{}-{}",
                filerow.id,
                Path::new(&filerow.filename)
                    .with_extension(dest_extension.clone())
                    .to_string_lossy()
            );

            // Convert the end user filename from the pre-transcode format to post-transcode format.
            debug!(
                "Destination length is {} ({:1.1}%)",
                dest_filesize,
                dest_filesize as f32 / filerow.filesize as f32 * 100.0
            );

            let dest_filerow_tmp = FileRow {
                contenthash: dest_content_hash.clone(),
                filename: dest_filename.clone(),
                filesize: dest_filesize,
                mimetype: dest_content_type.clone(),
                ..filerow.clone()
            };
            let dest_filerow = FileRow {
                pathnamehash: dest_filerow_tmp.pathnamehash(),
                ..dest_filerow_tmp
            };

            let time = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_micros() as i64;
            let insert_sql = format!(
                "insert into {}files (
                    contenthash,
                    pathnamehash,
                    contextid,
                    component,
                    filearea,
                    itemid,
                    filepath,
                    filename,
                    userid,
                    filesize,
                    mimetype,
                    status,
                    source,
                    author,
                    license,
                    timecreated,
                    timemodified,
                    sortorder,
                    referencefileid
                ) VALUES (
                    $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13,
                    $14, $15, $16, $17, $18, $19)
                RETURNING id",
                db_prefix
            );
            let dest_id: i64 = match connection
                .query(
                    insert_sql.as_str(),
                    &[
                        &dest_filerow.contenthash,
                        &dest_filerow.pathnamehash,
                        &dest_filerow.contextid,
                        &dest_filerow.component,
                        &dest_filerow.filearea,
                        &dest_filerow.itemid,
                        &dest_filerow.filepath,
                        &dest_filerow.filename,
                        &dest_filerow.userid,
                        &dest_filerow.filesize,
                        &dest_filerow.mimetype,
                        &dest_filerow.status,
                        &dest_filerow.source,
                        &dest_filerow.author,
                        &dest_filerow.license,
                        &time,
                        &time,
                        &dest_filerow.sortorder,
                        &dest_filerow.referencefileid,
                    ],
                )
                .await
            {
                Ok(rows) => rows.first().unwrap().get(0),
                Err(error) => {
                    error!("Database error while updating: {}", error);
                    return Err(Error::new(ErrorKind::Other, error));
                }
            };

            // Update reference file ID of the converted file to point to the destination.
            let update_referencefileids_sql = format!(
                "UPDATE {}files SET referencefileid = $1 WHERE id = $2",
                db_prefix
            );

            if let Err(error) = connection
                .execute(
                    update_referencefileids_sql.as_str(),
                    &[&dest_id, &filerow.id],
                )
                .await
            {
                error!("Database error while updating: {}", error);
                return Err(Error::new(ErrorKind::Other, error));
            }

            // Update the contents to point to the new file.
            let path_to_replace = format!("@@PLUGINFILE@@/{}", filerow.filename);
            let path_replacement = format!("@@PLUGINFILE@@/{}", dest_filerow.filename);

            // Replace the references to the old files in the course content.
            let updates_sql = vec![
                format!(
                    "UPDATE {}label
                    SET intro = REPLACE(intro, $1, $2)
                    WHERE ID=$3",
                    db_prefix
                ),
                format!(
                    "UPDATE {}page
                    SET intro = REPLACE(intro, $1, $2),
                        content = REPLACE(content, $1, $2)
                    WHERE ID=$3",
                    db_prefix
                ),
                format!(
                    "UPDATE {}forum_posts
                    SET message = REPLACE(message, $1, $2)
                    WHERE ID=$3",
                    db_prefix
                ),
            ];
            for update_sql in updates_sql {
                if let Err(error) = connection
                    .execute(
                        update_sql.as_str(),
                        &[&path_to_replace, &path_replacement, &dest_filerow.itemid],
                    )
                    .await
                {
                    error!("Database error while updating: {}", error);
                    return Err(Error::new(ErrorKind::Other, error));
                }
            }

            // File activities assumes the lowest ID with the correct context id, component
            // and file area is the one to use. The old file row ID will be be replaced
            // with one much higer so the Moodle module picks up the right version of the file.
            if filerow.component == "mod_resource" && filerow.filearea == "content" {
                let new_id = filerow.id + 100000000;
                let update_sql = format!("UPDATE {}files SET id=$1 WHERE ID=$2", db_prefix,);
                if let Err(error) = connection
                    .execute(update_sql.as_str(), &[&new_id, &filerow.id])
                    .await
                {
                    error!("Database error while updating resources: {}", error);
                    return Err(Error::new(ErrorKind::Other, error));
                }
            }

            trace!(
                "\tdestination {:?} is {} bytes",
                dest_filerow.filename,
                dest_filesize
            );
        }

        if run_once {
            break;
        } else {
            let delay_duration = Duration::from_millis((delay * 1000) as u64);
            if verbosity > 2 {
                println!("Pausing for {:?}", delay_duration);
            }
            time::sleep(delay_duration).await;
        }
    }

    Ok(())
}

impl FileRow {
    /// Convert the source file and write it into the temporary file.
    fn convert(
        &self,
        conversion: &Conversion,
        filedir_path: &PathBuf,
        temp_file: &PathBuf,
    ) -> Result<ExitStatus, std::io::Error> {
        let source_path = hashed_path(&filedir_path, self.contenthash.as_str());
        let source_length = source_path.metadata()?.len();
        trace!("\tsource file {:?} is {} bytes", source_path, source_length);

        // Spawn the transcoder.
        let mut command_program = Command::new("ffmpeg");
        let command_start = command_program
            .args(&["-loglevel", "24"]) // Warnings
            .arg("-y") // Overwrite without asking
            .arg("-i")
            .arg(source_path);
        let command_middle = if conversion.dest_content_type.starts_with("video/") {
            // TODO: Make max height configurable
            command_start
                .args(&["-vf", "scale='-2':'1000'"]) // Maximum dimension
                .args(&["-vcodec", "h264", "-acodec", "copy"])
        } else if conversion.dest_content_type.starts_with("audio/") {
            command_start
                .args(&["-vn"]) // Discard all video
                .args(&["-b:a", "128k"]) // Bitrate
        } else {
            return Err(std::io::Error::new(
                ErrorKind::InvalidInput,
                format!("Unsupported content type {}", conversion.dest_content_type),
            ));
        };

        let command = command_middle
            .args(&["-f", conversion.dest_extension.as_str()])
            .arg(&temp_file);
        trace!("Transcoding with command {:?}", command);
        command.status()
    }
}

fn hashed_path(filedir_path: &PathBuf, hash: &str) -> PathBuf {
    filedir_path
        .clone()
        .join("filedir")
        .join(&hash[0..2])
        .join(&hash[2..4])
        .join(&hash)
}

fn to_hex_string(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(2 * bytes.len());
    for byte in bytes {
        write!(result, "{:02x}", byte).unwrap();
    }
    result
}
