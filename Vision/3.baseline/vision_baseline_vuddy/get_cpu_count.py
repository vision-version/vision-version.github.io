def get_cpu_count():
    try:
        import multiprocessing
        return multiprocessing.cpu_count()
    except (ImportError, NotImplementedError):
        pass

    try:
        import psutil
        return psutil.cpu_count()
    except (ImportError, AttributeError):
        pass

    return 1
