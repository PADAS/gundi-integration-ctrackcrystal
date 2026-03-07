"""
CLI for the Ctrack Crystal API using the ctrackcrystal client.

Run with:
  python -m app.cli.ctrackcrystal [OPTIONS] COMMAND [ARGS]

Credentials can be passed via options or environment variables:
  CTRACK_BASE_URL, CTRACK_USERNAME, CTRACK_PASSWORD, CTRACK_SUBSCRIPTION_KEY
"""
import asyncio
import json
import os
import click

from app.datasource import ctrackcrystal

DEFAULT_BASE_URL = ctrackcrystal.BASE_URL


def _get_credentials(base_url, username, password, subscription_key):
    """Resolve credentials from options and environment."""
    url = base_url or os.environ.get("CTRACK_BASE_URL") or DEFAULT_BASE_URL
    user = username or os.environ.get("CTRACK_USERNAME")
    pwd = password or os.environ.get("CTRACK_PASSWORD")
    sub = subscription_key or os.environ.get("CTRACK_SUBSCRIPTION_KEY")
    if not all([user, pwd, sub]):
        raise click.UsageError(
            "Missing credentials. Set --base-url, --username, --password, --subscription-key "
            "or env vars CTRACK_USERNAME, CTRACK_PASSWORD, CTRACK_SUBSCRIPTION_KEY (and optionally CTRACK_BASE_URL)."
        )
    return url, user, pwd, sub


async def _get_token(base_url, username, password, subscription_key):
    """Obtain JWT token; raise on failure."""
    login_resp = await ctrackcrystal.login(base_url, username, password, subscription_key)
    if login_resp is None:
        raise click.ClickException("Failed to obtain token (check credentials).")
    return login_resp.jwt


@click.group()
@click.option(
    "--base-url",
    envvar="CTRACK_BASE_URL",
    default=DEFAULT_BASE_URL,
    show_default=True,
    help="Ctrack Crystal API base URL (without /api).",
)
@click.option("--username", envvar="CTRACK_USERNAME", help="API username.")
@click.option("--password", envvar="CTRACK_PASSWORD", help="API password.")
@click.option(
    "--subscription-key",
    envvar="CTRACK_SUBSCRIPTION_KEY",
    help="Ocp-Apim-Subscription-Key header value.",
)
@click.pass_context
def cli(ctx, base_url, username, password, subscription_key):
    """Query Ctrack Crystal API for vehicles and trip data (ctrackcrystal client)."""
    ctx.obj = (base_url, username, password, subscription_key)


@cli.command("vehicles")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
@click.pass_obj
def cmd_vehicles(creds, as_json):
    """List all vehicles (GetVehicles)."""
    base_url, username, password, subscription_key = _get_credentials(*creds)

    async def run():
        token = await _get_token(base_url, username, password, subscription_key)
        return await ctrackcrystal.get_vehicles(base_url, token, subscription_key)

    try:
        resp = asyncio.run(run())
    except ctrackcrystal.ClientBaseException as e:
        raise click.ClickException(f"API error: {e}") from e

    if as_json:
        data = {"count": resp.count, "vehicles": [v.dict() for v in resp.vehicles]}
        click.echo(json.dumps(data, default=str, indent=2))
        return

    click.echo(f"Vehicles ({resp.count}):")
    for v in resp.vehicles:
        last = v.last_reported_time.isoformat() if v.last_reported_time else "-"
        click.echo(
            f"  {v.id}  {v.display_name}  sn={v.serial_number}  "
            f"fleet={v.fleet_number or '-'}  reg={v.registration_number or '-'}  lastReported={last}"
        )


@cli.command("trips")
@click.option(
    "--vehicle-id",
    "vehicle_ids",
    multiple=True,
    required=True,
    help="Vehicle ID (can be repeated for batch).",
)
@click.option(
    "--date",
    "filter_date",
    required=True,
    type=click.DateTime(formats=["%Y-%m-%d"]),
    help="Filter day in UTC (YYYY-MM-DD).",
)
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
@click.pass_obj
def cmd_trips(creds, vehicle_ids, filter_date, as_json):
    """List trips for one or more vehicles on a given UTC day (Vehicle/Trips batch)."""
    base_url, username, password, subscription_key = _get_credentials(*creds)
    vehicle_ids_list = list(vehicle_ids)
    filter_day = filter_date.date()

    async def run():
        token = await _get_token(base_url, username, password, subscription_key)
        return await ctrackcrystal.get_trips(
            base_url, token, subscription_key, vehicle_ids_list, filter_day
        )

    try:
        resp = asyncio.run(run())
    except ctrackcrystal.ClientBaseException as e:
        raise click.ClickException(f"API error: {e}") from e

    if as_json:
        data = {
            "count": resp.count,
            "payload": [t.dict() for t in resp.payload],
        }
        click.echo(json.dumps(data, default=str, indent=2))
        return

    click.echo(f"Trips for {len(vehicle_ids_list)} vehicle(s) on {filter_day} ({resp.count}):")
    for t in resp.payload:
        click.echo(f"  Trip id={t.id}  distance={t.total_distance}  max_speed={t.max_speed}")
        for d in t.details:
            click.echo(
                f"    detail tripId={d.trip_id}  start={d.trip_start_time}  end={d.trip_end_time}  "
                f"distance={d.distance_driven}"
            )


@cli.command("trip-summary")
@click.option("--trip-id", required=True, help="Trip ID from the trips command.")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
@click.pass_obj
def cmd_trip_summary(creds, trip_id, as_json):
    """Fetch detailed trip summary (location points) for a trip (DetailedTripSummary)."""
    base_url, username, password, subscription_key = _get_credentials(*creds)

    async def run():
        token = await _get_token(base_url, username, password, subscription_key)
        return await ctrackcrystal.get_detailed_trip_summary(
            base_url, token, subscription_key, trip_id
        )

    try:
        resp = asyncio.run(run())
    except ctrackcrystal.ClientBaseException as e:
        raise click.ClickException(f"API error: {e}") from e

    points = resp.location_summary
    if as_json:
        data = {"locationSummary": [p.dict() for p in points]}
        click.echo(json.dumps(data, default=str, indent=2))
        return

    click.echo(f"Trip summary for {trip_id} ({len(points)} points):")
    for p in points:
        click.echo(
            f"  {p.event_time}  lat={p.latitude} lon={p.longitude}  "
            f"speed={p.speed}  heading={p.heading}  {p.event_text or ''}"
        )


def main():
    cli()


if __name__ == "__main__":
    main()
