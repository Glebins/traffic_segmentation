import psutil, time
for p in psutil.process_iter(['pid','ppid','name','cmdline','create_time','cpu_percent']):
    if 'python' in (p.info['name'] or '').lower():
        print(p.info)
