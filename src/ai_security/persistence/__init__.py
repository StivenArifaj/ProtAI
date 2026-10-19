"""Persistence layer (ADR-005, ADR-006): async SQLAlchemy 2.x + asyncpg.

Submodules: ``database`` (engine/session factory), ``models`` (mapped tables),
``nonce_repository`` (host-auth replay protection), ``audit_repository`` (ADR-002
append scaffolding with the transaction-scoped advisory-lock protocol).
"""
