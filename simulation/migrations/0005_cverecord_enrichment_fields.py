from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('simulation', '0004_remove_risksnapshot_compliance_score_and_more'),
    ]

    operations = [
        migrations.AddField(
            model_name='cverecord',
            name='affected_entries',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name='cverecord',
            name='cisa_kev',
            field=models.BooleanField(default=False),
        ),
        migrations.AddField(
            model_name='cverecord',
            name='cvss_version',
            field=models.CharField(blank=True, default='3.1', max_length=10),
        ),
        migrations.AddField(
            model_name='cverecord',
            name='exploit_confidence',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='cverecord',
            name='exploit_maturity',
            field=models.CharField(blank=True, default='unknown', max_length=20),
        ),
        migrations.AddField(
            model_name='cverecord',
            name='exploit_sources',
            field=models.JSONField(blank=True, default=list),
        ),
        migrations.AddField(
            model_name='cverecord',
            name='nvd_status',
            field=models.CharField(default='Analyzed', max_length=50),
        ),
        migrations.AddField(
            model_name='cverecord',
            name='patch_confidence',
            field=models.IntegerField(default=0),
        ),
        migrations.AddField(
            model_name='cverecord',
            name='patch_sources',
            field=models.JSONField(blank=True, default=list),
        ),
    ]
