from django.apps import AppConfig


class SimulationConfig(AppConfig):
    name = 'simulation'
    default_auto_field = 'django.db.models.BigAutoField'

    def ready(self):
        import threading
        import time

        def delayed_load():
            # Small delay to ensure DB is ready
            time.sleep(3)
            load_integrations_from_db()

        t = threading.Thread(target=delayed_load, daemon=True)
        t.start()


def load_integrations_from_db():
    """Load all saved integrations from DB into memory on startup"""
    try:
        from .models import IntegrationConfig
        from .services.integrations import get_integration_manager

        manager = get_integration_manager()
        configs = IntegrationConfig.objects.filter(is_enabled=True)
        count = configs.count()

        for cfg in configs:
            t    = cfg.integration_type
            data = cfg.config_data
            name = cfg.name
            try:
                if t == 'slack':
                    manager.configure_slack(
                        webhook_url=data.get('webhook_url', ''),
                        name=name
                    )
                elif t == 'jira':
                    manager.configure_jira(
                        base_url=data.get('base_url', ''),
                        email=data.get('email', ''),
                        api_token=data.get('api_token', ''),
                        project_key=data.get('project_key', ''),
                        name=name
                    )
                elif t == 'pagerduty':
                    manager.configure_pagerduty(
                        integration_key=data.get('integration_key', ''),
                        name=name
                    )
                elif t == 'webhook':
                    manager.configure_webhook(
                        name=name,
                        url=data.get('url', ''),
                        secret=data.get('secret') or None,
                        headers=data.get('headers') or None
                    )
                print(f"[CascadeX] Loaded integration: {t}:{name}")
            except Exception as e:
                print(f"[CascadeX] Failed to load {t}:{name} → {e}")

        manager.start()
        print(f"[CascadeX] Integration worker started with {count} integrations.")

    except Exception as e:
        print(f"[CascadeX] Integration load error: {e}")
