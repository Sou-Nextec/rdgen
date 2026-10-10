from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('rdgenerator', '0003_githubrun_outputs')]

    operations = [
        migrations.CreateModel(
            name='SavedModel',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('owner', models.EmailField(db_index=True, max_length=254)),
                ('name', models.CharField(max_length=80)),
                ('settings', models.JSONField(default=dict)),
                ('updated_at', models.DateTimeField(auto_now=True)),
            ],
            options={'ordering': ['name']},
        ),
        migrations.AddConstraint(
            model_name='savedmodel',
            constraint=models.UniqueConstraint(fields=('owner', 'name'), name='saved_model_owner_name'),
        ),
    ]
