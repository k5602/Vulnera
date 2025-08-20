create table cache_entries (
  id bigint primary key generated always as identity,
  key text not null unique,
  value text not null,
  created_at timestamp with time zone default now(),
  expires_at timestamp with time zone
);

create table cache_metadata (
  id bigint primary key generated always as identity,
  namespace text not null unique,
  policy text not null
);

create table cache_statistics (
  id bigint primary key generated always as identity,
  cache_hits bigint default 0,
  cache_misses bigint default 0,
  last_reset timestamp with time zone default now()
);

create table cache_locks (
  id bigint primary key generated always as identity,
  lock_name text not null unique,
  acquired_at timestamp with time zone default now(),
  released_at timestamp with time zone
);

create table cache_warming_jobs (
  id bigint primary key generated always as identity,
  job_name text not null unique,
  scheduled_at timestamp with time zone not null,
  status text not null
);

create table cache_audit_log (
  id bigint primary key generated always as identity,
  operation text not null,
  performed_at timestamp with time zone default now(),
  details text
);