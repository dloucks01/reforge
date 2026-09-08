"""Engagement tracking: a persistent record of hosts, credentials, and a timeline,
with a shareable report. Aggregates what the tool observed across a session."""

from reforge.engage.engagement import Engagement, Event

__all__ = ["Engagement", "Event"]
