from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('rdgenerator', '0005_generation_catalog')]

    operations = [
        migrations.AddField(
            model_name='githubrun',
            name='imported_at',
            field=models.DateTimeField(blank=True, null=True),
        ),
    ]
