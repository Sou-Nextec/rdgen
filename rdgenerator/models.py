from django.db import models

class GithubRun(models.Model):
    id = models.AutoField(verbose_name="ID", primary_key=True)
    uuid = models.CharField(verbose_name="uuid", max_length=100)
    status = models.CharField(verbose_name="status", max_length=100)
    github_run_id = models.BigIntegerField(null=True, blank=True)
    filename = models.CharField(max_length=255, default='', blank=True)
    platform = models.CharField(max_length=32, default='', blank=True)
    # Safe catalog metadata only. Build inputs and credentials stay out of this model.
    created_by = models.EmailField(max_length=254, blank=True, default='', db_index=True)
    client_name = models.CharField(max_length=120, blank=True, default='')
    # Preenchido quando o painel baixa o MSI para Atualizações: excluir depois disso exige confirmação explícita.
    imported_at = models.DateTimeField(null=True, blank=True)
    profile = models.CharField(max_length=32, blank=True, default='', choices=[
        ('default', 'Padrão'), ('client', 'Cliente'), ('analysts', 'Analistas'),
    ])
    rustdesk_version = models.CharField(max_length=32, blank=True, default='')
    package_version = models.CharField(max_length=32, blank=True, default='')
    generator_version = models.CharField(max_length=32, blank=True, default='')
    created_at = models.DateTimeField(auto_now_add=True, db_index=True, null=True)
    submission_error = models.TextField(blank=True, default='')
    notes = models.CharField(max_length=1000, blank=True, default='')
    # Nome do aplicativo (nao secreto). Vazio em itens anteriores a este campo; 'Tentar de novo' usa para nao trocar o protocolo.
    app_name = models.CharField(max_length=64, blank=True, default='')


class SavedModel(models.Model):
    owner = models.EmailField(db_index=True)
    name = models.CharField(max_length=80)
    settings = models.JSONField(default=dict)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        constraints = [models.UniqueConstraint(fields=['owner', 'name'], name='saved_model_owner_name')]
        ordering = ['name']
