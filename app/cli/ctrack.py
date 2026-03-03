"""
CLI for the Ctrack Crystal API datasource.

Run with:
  python -m app.cli.ctrack [OPTIONS] COMMAND [ARGS]

Credentials can be passed via options or environment variables:
  CTRACK_BASE_URL, CTRACK_USERNAME, CTRACK_PASSWORD, CTRACK_SUBSCRIPTION_KEY
"""
import asyncio
import json
import os
from datetime import datetime

import click

from app.datasource import ctrack

DEFAULT_BASE_URL = "https://apim.ctrackcrystal.com/api"


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
    login = await ctrack.get_token(base_url, username, password, subscription_key)
    if login is None:
        raise click.ClickException("Failed to obtain token (check credentials).")
    return login.jwt


@click.group()
@click.option(
    "--base-url",
    envvar="CTRACK_BASE_URL",
    default=DEFAULT_BASE_URL,
    show_default=True,
    help="Ctrack API base URL.",
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
    """Query Ctrack Crystal API for vehicles and trip data."""
    try:
        ctx.obj = _get_credentials(base_url, username, password, subscription_key)
    except click.UsageError as e:
        raise click.UsageError(str(e)) from e


@cli.command("vehicles")
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
@click.pass_obj
def cmd_vehicles(creds, as_json):
    """List all vehicles."""
    base_url, username, password, subscription_key = creds

    async def run():
        token = await _get_token(base_url, username, password, subscription_key)
        resp = await ctrack.get_vehicles(token, subscription_key, base_url)
        return resp

    try:
        resp = asyncio.run(run())
    except ctrack.ClientBaseException as e:
        raise click.ClickException(f"API error: {e}") from e

    if as_json:
        data = {"count": resp.count, "vehicles": [v.dict() for v in resp.vehicles]}
        click.echo(json.dumps(data, default=str, indent=2))
        return

    click.echo(f"Vehicles ({resp.count}):")
    for v in resp.vehicles:
        click.echo(
            f"  {v.id}  {v.display_name}  sn={v.serial_number}  "
            f"fleet={v.fleet_number or '-'}  reg={v.registration_number or '-'}"
        )


@cli.command("trips")
@click.option("--vehicle-id", required=True, help="Vehicle ID.")
@click.option(
    "--date",
    "filter_date",
    required=True,
    type=click.DateTime(formats=["%Y-%m-%d"]),
    help="Filter day (YYYY-MM-DD).",
)
@click.option("--json", "as_json", is_flag=True, help="Output raw JSON.")
@click.pass_obj
def cmd_trips(creds, vehicle_id, filter_date, as_json):
    """List trips for a vehicle on a given day."""
    base_url, username, password, subscription_key = creds
    filter_day = filter_date.replace(tzinfo=None) if filter_date.tzinfo else filter_date

    async def run():
        token = await _get_token(base_url, username, password, subscription_key)
        resp = await ctrack.get_vehicle_trips(
            token, subscription_key, base_url, vehicle_id, filter_day
        )
        return resp

    try:
        resp = asyncio.run(run())
    except ctrack.ClientBaseException as e:
        raise click.ClickException(f"API error: {e}") from e

    if as_json:
        data = {
            "count": resp.count,
            "payload": [t.dict() for t in resp.payload],
        }
        click.echo(json.dumps(data, default=str, indent=2))
        return

    click.echo(f"Trips for vehicle {vehicle_id} on {filter_day.date()} ({resp.count}):")
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
    """Fetch detailed trip summary (location points) for a trip."""
    base_url, username, password, subscription_key = creds

    async def run():
        token = await _get_token(base_url, username, password, subscription_key)
        resp = await ctrack.get_trip_summary(
            token, subscription_key, base_url, trip_id
        )
        return resp

    try:
        resp = asyncio.run(run())
    except ctrack.ClientBaseException as e:
        raise click.ClickException(f"API error: {e}") from e

    if as_json:
        data = {"locationSummary": [p.dict() for p in resp.locationSummary]}
        click.echo(json.dumps(data, default=str, indent=2))
        return

    click.echo(f"Trip summary for {trip_id} ({len(resp.locationSummary)} points):")
    for p in resp.locationSummary:
        click.echo(
            f"  {p.event_time}  lat={p.latitude} lon={p.longitude}  "
            f"speed={p.speed}  heading={p.heading}  {p.event_text or ''}"
        )


def main():
    cli()


if __name__ == "__main__":
    main()
