from django.db import models

class GithubRun(models.Model):
    id = models.IntegerField(verbose_name="ID",primary_key=True)
    uuid = models.CharField(verbose_name="uuid", max_length=100)
    status = models.CharField(verbose_name="status", max_length=100)
    github_run_id = models.BigIntegerField(null=True, blank=True)
    filename = models.CharField(max_length=255, default='', blank=True)
    platform = models.CharField(max_length=32, default='', blank=True)
