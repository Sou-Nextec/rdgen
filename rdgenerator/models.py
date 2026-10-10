from django.db import models

class GithubRun(models.Model):
    id = models.IntegerField(verbose_name="ID",primary_key=True)
    uuid = models.CharField(verbose_name="uuid", max_length=100)
    status = models.CharField(verbose_name="status", max_length=100)
    github_run_id = models.BigIntegerField(null=True, blank=True)
    filename = models.CharField(max_length=255, default='', blank=True)
    platform = models.CharField(max_length=32, default='', blank=True)


class SavedModel(models.Model):
    owner = models.EmailField(db_index=True)
    name = models.CharField(max_length=80)
    settings = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['owner', 'name'], name='saved_model_owner_name')]
        ordering = ['name']
