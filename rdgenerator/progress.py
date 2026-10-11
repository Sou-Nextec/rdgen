"""Progress is completed workflow steps, never elapsed-time simulation."""
TERMINAL = {'failure', 'cancelled', 'timed_out', 'action_required', 'skipped', 'incomplete'}


def workflow_progress(jobs, status, received_files=False):
    if status == 'success' and received_files:
        return {'percent': 100, 'stage': 'Instaladores disponíveis', 'failed_step': ''}
    steps = [step for job in jobs if job.get('name') != 'cleanup'
             for step in job.get('steps', [])
             if not step.get('name', '').startswith(('Post ', 'Complete job', 'Set up job'))
             and step.get('conclusion') != 'skipped']
    done = sum(step.get('status') == 'completed' and step.get('conclusion') == 'success' for step in steps)
    percent = min(99, int(100 * done / len(steps))) if steps else None
    failed = next((step['name'] for step in steps if step.get('conclusion') == 'failure'), '')
    active = next((step['name'] for step in steps if step.get('status') == 'in_progress'), '')
    stage = 'Falha na etapa: ' + failed if failed else active or ('Aguardando execução' if status not in TERMINAL else 'Geração interrompida')
    return {'percent': percent, 'stage': stage, 'failed_step': failed}
