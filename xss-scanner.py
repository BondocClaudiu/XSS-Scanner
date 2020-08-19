from scanner import Menu

if __name__ == "__main__":
    try:
        menu = Menu()
        menu.open()
    except KeyboardInterrupt:
        exit()
