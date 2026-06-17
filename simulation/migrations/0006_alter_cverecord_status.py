from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('simulation', '0005_cverecord_enrichment_fields'),
    ]

    operations = [
        migrations.AlterField(
            model_name='cverecord',
            name='status',
            field=models.CharField(
                choices=[
                    ('operational', 'Operational'),
                    ('elevated', 'Elevated'),
                    ('warning', 'Warning'),
                    ('critical', 'Critical'),
                    ('exploited', 'Exploited'),
                    ('not_applicable', 'Not Applicable'),
                    ('mitigated', 'Mitigated'),
                ],
                default='warning',
                max_length=20,
            ),
        ),
    ]
