from django.db import migrations, models


class Migration(migrations.Migration):
    dependencies = [('rdgenerator', '0004_savedmodel')]

    operations = [
        migrations.AlterField(
            model_name='githubrun',
            name='id',
            field=models.AutoField(primary_key=True, serialize=False, verbose_name='ID'),
        ),
        migrations.AddField(
            model_name='githubrun',
            name='created_by',
            field=models.EmailField(blank=True, db_index=True, default='', max_length=254),
        ),
        migrations.AddField(
            model_name='githubrun',
            name='client_name',
            field=models.CharField(blank=True, default='', max_length=120),
        ),
        migrations.AddField(
            model_name='githubrun',
            name='profile',
            field=models.CharField(blank=True, choices=[('default', 'Padrão'), ('client', 'Cliente'), ('analysts', 'Analistas')], default='', max_length=32),
        ),
        migrations.AddField(
            model_name='githubrun',
            name='rustdesk_version',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='githubrun',
            name='package_version',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='githubrun',
            name='generator_version',
            field=models.CharField(blank=True, default='', max_length=32),
        ),
        migrations.AddField(
            model_name='githubrun',
            name='created_at',
            field=models.DateTimeField(db_index=True, null=True),
        ),
        migrations.AlterField(
            model_name='githubrun',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, db_index=True, null=True),
        ),
        migrations.AddField(
            model_name='githubrun',
            name='submission_error',
            field=models.TextField(blank=True, default=''),
        ),
        migrations.AddField(
            model_name='githubrun',
            name='notes',
            field=models.CharField(blank=True, default='', max_length=1000),
        ),
    ]
