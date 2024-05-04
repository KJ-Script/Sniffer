def end_flow(flags):
    if flags is not None:
        for items in flags:
            if items == "FIN" or items == "RST":
                return True

