from app import app
from flask import Flask

app.config.from_object('def_settings')

#if 'SENTRY_DSN' in app.config:
#    import sentry_sdk
#    from sentry_sdk.integrations.flask import FlaskIntegration
#    sentry_dsn = app.config['SENTRY_DSN']
#    sentry_pii = app.config['SENTRY_PII']
#    sentry_debug = app.config['SENTRY_DEBUG']
#    sentry_release = app.config['SENTRY_RELEASE']
#
#    sentry_sdk.init(
#        dsn=sentry_dsn,
#        send_default_pii=sentry_pii,
#        debug=sentry_debug,
#        release=sentry_release,
#        integrations=[
#            FlaskIntegration(),
#        ],

        # Set traces_sample_rate to 1.0 to capture 100%
        # of transactions for performance monitoring.
        # We recommend adjusting this value in production.
#        traces_sample_rate=1.0
#    )

if __name__ == "__main__":
    app.run()
