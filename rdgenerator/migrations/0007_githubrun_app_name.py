from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('rdgenerator', '0006_githubrun_imported_at')]

    operations = [
        migrations.AddField(
            model_name='githubrun',
            name='app_name',
            field=models.CharField(blank=True, default='', max_length=64),
        ),
    ]
