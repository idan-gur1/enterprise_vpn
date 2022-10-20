import datetime


class Logger:
    def __init__(self, log_file_base_name, init_msg):
        self.base_name = log_file_base_name

        self.run_date = datetime.datetime.now().strftime("%Y_%m_%d")

        self.__log(f"\n\n{datetime.datetime.now().strftime('%H:%M:%S')}_{init_msg}\n\n", True, False)

    def __log(self, data, output_to_stdout=False, time=True):
        """
        print the data to standard output and saves to log file of the day with the time
        :param data: str - data to output
        :param output_to_stdout: bool - if print to screen
        :return:
        """
        if output_to_stdout:
            print(data)

        with open(f"{self.run_date}_{self.base_name}.log", "a") as f:
            f.write(f"{datetime.datetime.now().strftime('%H:%M:%S')+'_' if time else ''}{data}\n")

    def debug(self, data):
        self.__log(f"DEBUG: {data}", True)

    def error(self, data):
        self.__log(f"ERROR: {data}", True)

    def info(self, data, output_to_stdout=False):
        self.__log(f"INFO: {data}", output_to_stdout)

    def warning(self, data, output_to_stdout=False):
        self.__log(f"WARNING: {data}", output_to_stdout)
