// RouterLab: Orchestration Layer to Automate Experiments on Network Routers
// Copyright (C) 2022-2025 Tibor Schneider <sctibor@ethz.ch> and Roland Schmid <roschmi@ethz.ch>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

//! Implementation for starting the exabgp process.

use std::{
    process::Stdio,
    time::{Duration, Instant},
};

use tokio::{
    io::AsyncReadExt,
    process::{Child, ChildStderr, ChildStdout},
    time::timeout,
};

use crate::{
    config::CONFIG,
    ssh::{SshError, SshSession, EMPTY},
};

const START_TIMEOUT: Duration = Duration::from_secs(60);
const NUM_RETRY: usize = 2;

/// Handle to an exabgp instance
pub struct ExaBgpHandle {
    /// Handle to the SSH session.
    pub(super) session: SshSession,
    /// Number of neighbors configured
    num_sessions: usize,
    /// child process if the process is already running
    child: Option<Child>,
    /// child process of the tee commands
    redirects: Option<(Child, Child)>,
}

impl ExaBgpHandle {
    /// Create a new ExaBGP Handle. This will not yet start the process, but it will configure
    /// exabgp properly.
    pub(crate) async fn new<C>(handle: SshSession, config: C, runner: C) -> Result<Self, SshError>
    where
        C: AsRef<str> + AsRef<[u8]> + Send + Sync,
    {
        let num_sessions = str::lines(config.as_ref())
            .filter(|l| l.starts_with("neighbor"))
            .count();

        log::debug!(
            "[{}] Configuring exabgp with {} sessions",
            handle.name(),
            num_sessions
        );

        handle
            .write_file(&CONFIG.server.exabgp_config_filename, config)
            .await?;
        handle
            .write_file(&CONFIG.server.exabgp_runner_filename, runner)
            .await?;

        log::debug!("exabgp configured!");

        // create self
        let s = Self {
            session: handle,
            num_sessions,
            child: None,
            redirects: None,
        };
        // create the file
        write_step(&s.session, -1).await?;

        Ok(s)
    }

    /// Update the exabgp runner script and restart the exabgp process. The neighbor configuration
    /// of exabgp will remain unchanged.
    pub async fn update_runner(
        &mut self,
        runner: impl AsRef<[u8]> + Send + Sync,
    ) -> Result<(), SshError> {
        log::debug!("[{}] stop exabgp", self.session.name());
        // create a copy of self, in order to kill it while still keeping `self`.
        let self_clone = Self {
            session: self.session.clone(),
            num_sessions: self.num_sessions,
            child: self.child.take(),
            redirects: self.redirects.take(),
        };
        // kill the process
        self_clone.kill().await?;

        log::debug!("[{}] update the exabgp runner script", self.session.name());
        self.session
            .write_file(&CONFIG.server.exabgp_runner_filename, runner)
            .await?;

        // start exabgp again
        log::debug!("[{}] start exabgp", self.session.name());
        self.start().await
    }

    /// Access the `ExaBgpHandle`'s associated `SshSession`.
    pub fn get_ssh_session(&self) -> &SshSession {
        &self.session
    }

    /// Get the current step.
    pub async fn current_step(&self) -> Result<isize, SshError> {
        read_step(&self.session).await
    }

    /// Go to the next step in the exabgp execution
    pub async fn step(&self) -> Result<(), SshError> {
        let step = read_step(&self.session).await?;
        write_step(&self.session, step + 1).await
    }

    /// Start the ExaBGP Process. This will fail if you attemp to start the process multiple times!
    pub(crate) async fn start(&mut self) -> Result<(), SshError> {
        if self.child.is_some() {
            log::warn!("[{}] Skip starting exabgp twice.", self.session.name());
            return Ok(());
        }

        let mut iter = 0;
        'retry: loop {
            if iter >= NUM_RETRY {
                log::error!("[{}] Could not start exabgp!", self.session.name());
                return Err(SshError::CommandError(
                    self.session.name().to_string(),
                    format!("exabgp {}", &CONFIG.server.exabgp_config_filename),
                    255,
                ));
            }

            iter += 1;

            // first, kill all previous exabgp processes
            let _ = self
                .session
                .execute_cmd_status(&["sudo", "killall", "-9", "exabgp"])
                .await?;

            // execute the command
            log::debug!(
                "[{}] exabgp {}",
                self.session.name(),
                &CONFIG.server.exabgp_config_filename
            );

            let mut child = self
                .session
                .command("exabgp")
                .arg(&CONFIG.server.exabgp_config_filename)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped())
                .spawn()?;

            let start = Instant::now();

            // wait for the appropriate output
            log::trace!(
                "[{}] waiting for exabgp to setup all its sessions",
                self.session.name()
            );

            let mut stdout = child.stdout.take().unwrap();
            let mut stderr = child.stderr.take().unwrap();
            let mut buffer: Vec<u8> = Vec::new();

            // wait until we see `loaded new configuraiton successfully`
            self.expect_output(
                &mut buffer,
                &mut stdout,
                &mut stderr,
                "| loaded new configuration successfully",
                start,
            )
            .await?;

            // wait until we are connected with all peers
            for i in 1..=self.num_sessions {
                let exp = format!("| connected to peer-{i}");
                match self
                    .expect_output(&mut buffer, &mut stdout, &mut stderr, exp, start)
                    .await
                {
                    Ok(_) => {}
                    Err(_) => {
                        child.kill().await?;
                        tokio::time::sleep(Duration::from_secs(2)).await;
                        continue 'retry;
                    }
                }
            }

            // exabgp started successfully
            log::trace!("[{}] exabgp started successfully", self.session.name());

            // pipe the output into /dev/null
            let stdout_cat = tokio::process::Command::new("cat")
                .stdin(TryInto::<Stdio>::try_into(stdout)?)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()?;
            let stderr_cat = tokio::process::Command::new("cat")
                .stdin(TryInto::<Stdio>::try_into(stderr)?)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()?;

            // we have seen all connections! continue to the first step.
            self.step().await?;

            self.child = Some(child);
            self.redirects = Some((stdout_cat, stderr_cat));

            return Ok(());
        }
    }

    /// Gracefully kill the exabgp process by removing the control file.
    pub(crate) async fn kill(mut self) -> Result<(), SshError> {
        if let Some(mut child) = self.child.take() {
            child.kill().await?;
        }
        if let Some((mut stdout_redir, mut stderr_redir)) = self.redirects.take() {
            stdout_redir.kill().await?;
            stderr_redir.kill().await?;
        }

        // kill all exabgp sessions
        self.session
            .execute_cmd_status(&["sudo", "killall", "-9", "exabgp"])
            .await?;

        Ok(())
    }

    /// Wait until a specific output was received.
    async fn expect_output(
        &mut self,
        buffer: &mut Vec<u8>,
        stdout: &mut ChildStdout,
        stderr: &mut ChildStderr,
        target: impl AsRef<str>,
        start_time: Instant,
    ) -> Result<(), SshError> {
        while !String::from_utf8_lossy(buffer).contains(target.as_ref()) {
            let elapsed = start_time.elapsed();
            let to_deadline = if let Some(x) = START_TIMEOUT.checked_sub(elapsed) {
                x
            } else {
                log::warn!(
                    "[{}] exabgp could not load configuration successfully!\nStdout:\n{}",
                    self.session.name(),
                    String::from_utf8_lossy(buffer)
                );
                return Err(SshError::CommandError(
                    self.session.name().to_string(),
                    format!("exabgp {}", &CONFIG.server.exabgp_config_filename),
                    255,
                ));
            };

            match timeout(to_deadline, stdout.read_buf(buffer)).await {
                Ok(Ok(0)) => {
                    let mut s_stderr = String::new();
                    stderr.read_to_string(&mut s_stderr).await?;
                    log::error!(
                        "[{}] exabgp: Unexpected EOF!\nSTDOUT:\n{}STDERR:\n{}",
                        self.session.name(),
                        String::from_utf8_lossy(buffer),
                        s_stderr
                    );
                    return Err(SshError::CommandError(
                        self.session.name().to_string(),
                        format!("exabgp {}", &CONFIG.server.exabgp_config_filename),
                        255,
                    ));
                }
                Ok(Err(e)) => Err(e)?,
                // timeout occurred
                _ => {}
            }
        }

        Ok(())
    }
}

/// Write `step` into the control file.
pub(super) async fn write_step(session: &SshSession, step: isize) -> Result<(), SshError> {
    session
        .write_file(
            &CONFIG.server.exabgp_runner_control_filename,
            step.to_string() + "\n",
        )
        .await
}

/// Read `self.step` from the control file.
pub(super) async fn read_step(session: &SshSession) -> Result<isize, SshError> {
    let current_step = session
        .execute_cmd_stdout(&["cat", &CONFIG.server.exabgp_runner_control_filename])
        .await?;
    Ok(current_step.trim().parse().unwrap_or_default())
}

impl Drop for ExaBgpHandle {
    fn drop(&mut self) {
        // send the killall command
        log::trace!("[{}] killall exabgp (drop)", self.session.name());
        let _ = self
            .session
            .std_command(EMPTY)
            .args(["sudo", "killall", "-9", "exabgp"])
            .output();
    }
}
