from colorama import Fore, Style

class PrintOutput:
    def info(self, message: str):
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {message}")

    def success(self, message: str):
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")

    def error(self, message: str):
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")

    def warning(self, message: str):
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")

    def print_banner(self):
        banner = f"""
{Fore.MAGENTA}
 _                                     
| |                                    
| |     __ _ _ __ __ ___   _______  __ 
| |    / _` | '__/ _` \ \ / / _ \ \/ / 
| |___| (_| | | | (_| |\ V /  __/>  <  
\_____/\__,_|_|  \__,_| \_/ \___/_/\_\ 
                                       
{Style.RESET_ALL}
        """
        print(banner)

print_output = PrintOutput()
