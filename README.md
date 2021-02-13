# mootranscode

mootranscode replaces the uploaded version of video and audio files with
transcoded versions that can play anywhere. This avoids students needing
to be able to view every possible format, like requiring QuickTime for MOV
files on Windows.

The following conversions are currently done:

- video/quicktime (.mov) to MP4 video
- audio/ogg (.ogg) to MP4 audio

The MP4 versions of the files should work on any modern platform.

## Warning

This was created as a one-off to solve a particular problem. Your milage may
vary but contributions are always very welcome.

This application has only been tested with Moodle 3.10 running on Ubuntu with
PostgreSQL serving the database.

## Installation

[ffmpeg](https://ffmpeg.org/) must be installed to do the heavy lifting.

Compile the code with

```
$ cargo build --release
```

then move the binary from `target/release/mootrancode` to somewhere convenient
like `/usr/local/bin/`.

To run the application as a service using systemd create a file called
`/etc/systemd/system/mootranscode.service` substituting the name of the
appropriate user.

```
[Unit]
Description=Mootranscode
After=network.target
StartLimitIntervalSec=0[Service]
Type=simple
Restart=always
RestartSec=1
User=YOUR_USERNAME
ExecStart=/usr/local/bin/mootranscode --repeat

[Install]
WantedBy=multi-user.target
```

Start the service running using:

```
# systemctl start mootranscode
```

Enable the service to start at boot with

```
# systemctl enable mootranscode
```

## Running

The application must be able to read and write files in the Moodle data
directory and that the server can read. This may require running as a user
such as `moodle` or one in the `www-data` group.

By default the application runs once and exits. Continuosly poll the database
for new files by using the `--repeat` option.

Unless the current user can connect to the Moodle database without password
authentication you will need the `--dbpass` option.

For a full list of options run:

```
$ mootranscode -help
```

## License

Copyright 2021 Sheldon Young <sheldon@softdev.ca>

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.

## History

2020-02-12 Published to GitHub.
2020-02-09 Project started.
