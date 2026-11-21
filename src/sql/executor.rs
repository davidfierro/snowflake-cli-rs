//! The transport of one run (ADR 0005, Decision 1): the SQL API by default, a connector session
//! when the run needs one (a `PUT`/`GET` statement, or a sign-in the SQL API cannot take).

use super::{ClientOptions, ScriptOptions, ScriptRun, SqlClient};
use crate::auth::Credential;
use crate::connection::ConnectionConfig;
use crate::error::Result;
use crate::session::{
    BrowserOpener, CredentialCache, Interaction, Prompt, Session, SessionOptions,
};
use crate::sql::RowStream;
use crate::transfer::TransferOptions;
use std::time::SystemTime;

/// Hidden statement run first with [`ScriptOptions::autocommit_off`] (ADR 0005, Decision 1).
const AUTOCOMMIT_OFF: &str = "ALTER SESSION SET AUTOCOMMIT = FALSE";

/// The transport of one run.
pub enum Executor {
    SqlApi(SqlClient),
    Session(Session, TransferOptions),
}

/// What a run needs from its transport.
#[derive(Debug, Clone, Copy, Default)]
pub struct RunNeeds {
    /// A `PUT`/`GET` statement, a `!` command that needs one, or the interactive session.
    pub session: bool,
}

/// What an interactive sign-in uses: the test seams of ADR 0005 Decision 2.
pub struct SignInIo<'a> {
    pub prompt: &'a dyn Prompt,
    pub browser: &'a dyn BrowserOpener,
    pub cache: &'a dyn CredentialCache,
    /// `SessionOptions` that come from the connection and the environment (keep-alive, callback
    /// port).
    pub session: SessionOptions,
}

impl Executor {
    /// Picks the transport and, for a session, signs in. No network access for the SQL API.
    pub fn connect(
        conn: &ConnectionConfig,
        needs: RunNeeds,
        credential: Credential,
        options: ClientOptions,
        script: &ScriptOptions,
        transfer: TransferOptions,
        io: &SignInIo<'_>,
    ) -> Result<Self> {
        let bearer = match credential {
            Credential::Bearer(auth) if !needs.session => {
                return Ok(Self::SqlApi(SqlClient::new(conn, auth, options)?));
            }
            Credential::Bearer(auth) => Some(auth),
            Credential::Connector => None,
        };
        let session_options = SessionOptions {
            connect_timeout: options.connect_timeout,
            request_timeout: options.request_timeout,
            max_retries: options.max_retries,
            poll_interval_max: options.poll_interval_max,
            decimal_precision: options.decimal_precision,
            partition_concurrency: options.partition_concurrency,
            secondary_roles: script.secondary_roles,
            ..io.session.clone()
        };
        let interaction = Interaction {
            credential: bearer.as_deref(),
            prompt: io.prompt,
            browser: io.browser,
            cache: io.cache,
            clock: SystemTime::now,
        };
        Ok(Self::Session(
            Session::login(conn, session_options, &interaction)?,
            transfer,
        ))
    }

    /// Same contract as [`SqlClient::run_script`]; on a session the statements run one by one
    /// as the results are read, and `PUT`/`GET` results are rows too.
    pub fn run_script<'a>(
        &'a self,
        statements: &'a [String],
        options: &ScriptOptions,
    ) -> Result<Results<'a>> {
        match self {
            Self::SqlApi(client) => Ok(Results::SqlApi(client.run_script(statements, options)?)),
            Self::Session(session, transfer) => {
                if options.autocommit_off {
                    session.query(AUTOCOMMIT_OFF)?;
                }
                Ok(Results::Session(SessionRun {
                    session,
                    transfer,
                    statements: statements.iter(),
                    done: false,
                }))
            }
        }
    }

    /// The session, when the run is on one.
    pub fn session(&self) -> Option<&Session> {
        match self {
            Self::SqlApi(_) => None,
            Self::Session(session, _) => Some(session),
        }
    }

    /// Ends the session, if any.
    pub fn close(self) -> Result<()> {
        match self {
            Self::SqlApi(_) => Ok(()),
            Self::Session(session, _) => session.close(),
        }
    }
}

/// The results of a run, one per statement, in order.
pub enum Results<'a> {
    SqlApi(ScriptRun),
    Session(SessionRun<'a>),
}

impl Iterator for Results<'_> {
    type Item = Result<RowStream>;

    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Results::SqlApi(run) => run.next(),
            Results::Session(run) => run.next(),
        }
    }
}

/// Statements on a session: each runs when its result is asked for.
pub struct SessionRun<'a> {
    session: &'a Session,
    transfer: &'a TransferOptions,
    statements: std::slice::Iter<'a, String>,
    done: bool,
}

impl SessionRun<'_> {
    fn run(&self, statement: &str) -> Result<RowStream> {
        let response = self.session.query(statement)?;
        if response.transfer_command().is_some() {
            let result =
                crate::transfer::execute(self.session, statement, &response.data, self.transfer)?;
            return Ok(RowStream::from_result(result));
        }
        response.into_rows(self.session)
    }
}

impl Iterator for SessionRun<'_> {
    /// `Ok(stream)` for a statement that ran; `Err` for the failing one, then `None`.
    type Item = Result<RowStream>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }
        let statement = self.statements.next()?;
        let item = self.run(statement);
        self.done = item.is_err();
        Some(item)
    }
}
