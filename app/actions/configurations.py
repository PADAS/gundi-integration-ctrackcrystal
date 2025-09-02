import pydantic

from app.actions.core import AuthActionConfiguration, PullActionConfiguration
from app.services.errors import ConfigurationNotFound
from app.services.utils import find_config_for_action, FieldWithUIOptions, UIOptions, GlobalUISchemaOptions


class AuthenticateConfig(AuthActionConfiguration):
    subscription_key: pydantic.SecretStr = FieldWithUIOptions(
        title="Ctrack Crystal Subscription Key",
        description="A valid Ctrack Crystal API subscription key",
        ui_options=UIOptions(
            widget="password",
        ),
    )
    username: str = FieldWithUIOptions(
        title="Username",
        description="The username for the Ctrack Crystal account",
    )
    password: pydantic.SecretStr = FieldWithUIOptions(
        ...,
        title="Password",
        description="The password for the Ctrack Crystal account",
        ui_options=UIOptions(
            widget="password",
        ),
    )

    ui_global_options: GlobalUISchemaOptions = GlobalUISchemaOptions(
        order=[
            "subscription_key",
            "username",
            "password"
        ],
    )


class PullObservationsConfig(PullActionConfiguration):
    pass


class PullVehicleTripsConfig(PullActionConfiguration):
    vehicle_id: str
    vehicle_serial_number: str
    vehicle_display_name: str


def get_auth_config(integration):
    # Look for auth action
    auth_config = find_config_for_action(
        configurations=integration.configurations,
        action_id="auth"
    )
    if not auth_config:
        raise ConfigurationNotFound(
            f"Authentication settings for integration {str(integration.id)} "
            f"are missing. Please fix the integration setup in the portal."
        )
    return AuthenticateConfig.parse_obj(auth_config.data)


def get_pull_config(integration):
    # Look for the login credentials, needed for any action
    pull_config = find_config_for_action(
        configurations=integration.configurations,
        action_id="pull_observations"
    )
    if not pull_config:
        raise ConfigurationNotFound(
            f"Pull Observations settings for integration {str(integration.id)} "
            f"are missing. Please fix the integration setup in the portal."
        )
    return PullObservationsConfig.parse_obj(pull_config.data)
