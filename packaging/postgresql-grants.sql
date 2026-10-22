-- Apply as PostgreSQL administrator AFTER schema migration. Do not grant schema
-- ownership or membership in serverhub_migrate to a running service account.
REVOKE ALL ON DATABASE serverhub FROM PUBLIC;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT CONNECT ON DATABASE serverhub TO serverhub_api, serverhub_worker;
GRANT USAGE ON SCHEMA public TO serverhub_api, serverhub_worker;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO serverhub_api;
GRANT SELECT ON users, hosts, policies, jobs, job_events, audit, findings, incidents,
    memories, backups, agent_commands, system_state, inventory_samples, graph_edges
    TO serverhub_worker;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO serverhub_api, serverhub_worker;
GRANT INSERT ON audit TO serverhub_api, serverhub_worker;
GRANT INSERT, UPDATE, DELETE ON users, session_tokens, hosts, enrollments, policies,
    jobs, job_events, findings, incidents, memories, backups, agent_commands,
    system_state, inventory_samples, graph_edges TO serverhub_api;
GRANT INSERT, UPDATE ON jobs, job_events, findings, incidents, memories, agent_commands,
    inventory_samples, graph_edges TO serverhub_worker;
GRANT DELETE ON graph_edges, inventory_samples TO serverhub_worker;
-- Extension tables are granted explicitly after their migration; absent optional
-- tables must never cause a broad GRANT ALL shortcut.
DO $$ DECLARE relation text; BEGIN
  FOREACH relation IN ARRAY ARRAY['oauth_clients','oauth_pending','oauth_codes','oauth_refresh','schedules'] LOOP
    IF to_regclass('public.' || relation) IS NOT NULL THEN
      EXECUTE format('GRANT INSERT, UPDATE, DELETE ON TABLE %I TO serverhub_api', relation);
      IF relation = 'schedules' THEN
        EXECUTE format('GRANT SELECT, UPDATE ON TABLE %I TO serverhub_worker', relation);
      END IF;
    END IF;
  END LOOP;
END $$;
-- OAuth credentials and authorization codes are isolated from workers, including
-- reads. The API is the only running identity allowed to access these tables.
DO $$ DECLARE relation text; BEGIN
  FOREACH relation IN ARRAY ARRAY['oauth_clients','oauth_pending','oauth_codes','oauth_refresh'] LOOP
    IF to_regclass('public.' || relation) IS NOT NULL THEN
      EXECUTE format('REVOKE ALL ON TABLE %I FROM serverhub_worker', relation);
    END IF;
  END LOOP;
END $$;
REVOKE UPDATE, DELETE, TRUNCATE ON audit FROM serverhub_api, serverhub_worker;
REVOKE ALL ON session_tokens, enrollments FROM serverhub_worker;
REVOKE INSERT, UPDATE, DELETE, TRUNCATE ON users, session_tokens, policies,
    enrollments, system_state, backups FROM serverhub_worker;
ALTER DEFAULT PRIVILEGES FOR ROLE serverhub_migrate IN SCHEMA public
    GRANT SELECT ON TABLES TO serverhub_api;
ALTER DEFAULT PRIVILEGES FOR ROLE serverhub_migrate IN SCHEMA public
    GRANT USAGE, SELECT ON SEQUENCES TO serverhub_api, serverhub_worker;
