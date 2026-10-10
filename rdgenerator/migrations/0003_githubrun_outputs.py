from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('rdgenerator', '0002_githubrun_github_run_id')]
    operations = [
        migrations.AddField(model_name='githubrun', name='filename',
                            field=models.CharField(max_length=255, default='', blank=True)),
        migrations.AddField(model_name='githubrun', name='platform',
                            field=models.CharField(max_length=32, default='', blank=True)),
    ]
