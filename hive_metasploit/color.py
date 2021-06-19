# Description
"""
Color print in console
Author: Vladimir Ivanov
License: MIT
Copyright 2021, Hive Metasploit connector
"""

# Import
from colorama import Fore, Style
from threading import Lock

# Authorship information
__author__ = "Vladimir Ivanov"
__copyright__ = "Copyright 2021, Hive Metasploit connector"
__credits__ = [""]
__license__ = "MIT"
__version__ = "0.0.1a1"
__maintainer__ = "Vladimir Ivanov"
__email__ = "ivanov.vladimir.mail@gmail.com"
__status__ = "Development"


# Color class
class Color:

    info_prefix: str = f"{Style.BRIGHT}{Fore.BLUE}[*]{Style.RESET_ALL} "
    error_prefix: str = f"{Style.BRIGHT}{Fore.RED}[-]{Style.RESET_ALL} "
    success_prefix: str = f"{Style.BRIGHT}{Fore.GREEN}[+]{Style.RESET_ALL} "
    warning_prefix: str = f"{Style.BRIGHT}{Fore.YELLOW}[!]{Style.RESET_ALL} "

    def __init__(self):
        self._lock: Lock = Lock()

    def _color_print(self, color: Fore = Fore.BLUE, *strings: str) -> None:
        """
        Print colored text in console
        :param color: Set color: Fore.BLUE, Fore.RED, Fore.YELLOW, Fore.GREEN (default: Fore.BLUE)
        :param strings: Strings for printing in console
        :return: None
        """
        result_output_string: str = ""
        if color == Fore.BLUE:
            result_output_string += self.info_prefix
        elif color == Fore.RED:
            result_output_string += self.error_prefix
        elif color == Fore.YELLOW:
            result_output_string += self.warning_prefix
        elif color == Fore.GREEN:
            result_output_string += self.success_prefix
        else:
            result_output_string += self.info_prefix
        for index in range(len(strings)):
            if index % 2 == 0:
                result_output_string += strings[index]
            else:
                result_output_string += f"{color}{strings[index]}{Fore.RESET}"
            if not result_output_string.endswith(" "):
                result_output_string += " "
        self._lock.acquire()
        print(result_output_string)
        self._lock.release()

    @staticmethod
    def _color_text(color: Fore = Fore.BLUE, string: str = "") -> str:
        """
        Make colored string
        :param color: Set color: blue, red, yellow, green (default: blue)
        :param string: Input string (example: 'test')
        :return: Colored string (example: '\033[1;34mtest\033[0m')
        """
        return f"{color}{string}{Fore.RESET}"

    def print_info(self, *strings: str) -> None:
        """
        Print informational text in console
        :param strings: Strings for printing in console
        :return: None
        """
        self._color_print(Fore.BLUE, *strings)

    def print_error(self, *strings: str) -> None:
        """
        Print error text in console
        :param strings: Strings for printing in console
        :return: None
        """
        self._color_print(Fore.RED, *strings)

    def print_warning(self, *strings: str) -> None:
        """
        Print warning text in console
        :param strings: Strings for printing in console
        :return: None
        """
        self._color_print(Fore.YELLOW, *strings)

    def print_success(self, *strings: str) -> None:
        """
        Print success text in console
        :param strings: Strings for printing in console
        :return: None
        """
        self._color_print(Fore.GREEN, *strings)

    def print_progress_bar(
        self, current: int, total: int, bar_length: int = 20
    ) -> None:
        """
        Print progress bar in console
        :param current: Current value
        :param total: Total value
        :param bar_length: Length of progress bar
        :return: None
        """
        percent = float(current) * 100 / total
        arrow = "-" * int(percent / 100 * bar_length - 1) + ">"
        spaces = " " * (bar_length - len(arrow))
        print(
            self.info_prefix + "Progress: [%s%s] %d %%" % (arrow, spaces, percent),
            end="\r",
        )

    def info_text(self, text: str) -> str:
        """
        Make information text
        :param text: Input string (example: 'test')
        :return: Colored string (example: '\033[1;34mtest\033[0m')
        """
        return self._color_text(Fore.BLUE, text)

    def error_text(self, text: str) -> str:
        """
        Make error text
        :param text: Input string (example: 'test')
        :return: Colored string (example: '\033[1;31mtest\033[0m')
        """
        return self._color_text(Fore.RED, text)

    def warning_text(self, text: str) -> str:
        """
        Make warning text
        :param text: Input string (example: 'test')
        :return: Colored string (example: '\033[1;32mtest\033[0m')
        """
        return self._color_text(Fore.YELLOW, text)

    def success_text(self, text: str) -> str:
        """
        Make success text
        :param text: Input string (example: 'test')
        :return: Colored string (example: '\033[1;33mtest\033[0m')
        """
        return self._color_text(Fore.GREEN, text)
