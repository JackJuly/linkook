import queue
import threading

exit_event = threading.Event()

def set_exiting():
    """
    exit the program
    """
    exit_event.set()

class ScannerManager:
    def __init__(self, user, scanner, console_printer, args):
        self.user = user
        self.scanner = scanner
        self.console_printer = console_printer
        self.args = args
        self.results = {}
        self.num_threads = 5
        self.queue = queue.Queue()
        self.lock = threading.Lock() 

    def _process_provider(self, user, provider_name, other_links_flag):
        """
        process a provider and update the results (internal method)
        """
        if exit_event.is_set():
            return
        
        provider = self.scanner.all_providers.get(provider_name)
        if not provider:
            return

        # deep scan
        scan_result = self.scanner.deep_scan(user, provider)

        # print result
        if not self.args.silent:
            self.console_printer.update({
                "site_name": provider_name,
                "status": "FOUND" if scan_result["found"] else "NOT FOUND",
                "profile_url": scan_result["profile_url"],
                "other_links": scan_result.get("other_links", {}),
                "other_links_flag": other_links_flag,
                "infos": scan_result.get("infos", {}),
                "hibp": self.scanner.hibp_key,
            })

        # update results
        with self.lock:
            self.results[provider_name] = scan_result
        

        # add new tasks
        other_links = scan_result.get("other_links", {})
        for linked_provider, linked_urls in other_links.items():
            linked_provider_obj = self.scanner.all_providers.get(linked_provider)
            if not linked_provider_obj or not linked_provider_obj.is_connected:
                continue
            for url in linked_urls:
                if url in self.scanner.visited_urls:
                    continue
                new_user = linked_provider_obj.extract_user(url).pop()
                if new_user != user:
                    self.queue.put((new_user, linked_provider, True))

    def _worker(self):
        """
        worker thread to process tasks from the queue
        """
        while not exit_event.is_set():
            try:
                # add a timeout to avoid blocking forever
                user, provider, flag = self.queue.get(block=True, timeout=1)
                try:
                    self._process_provider(user, provider, flag)
                finally:
                    self.queue.task_done()
            except queue.Empty:
                break 
            except Exception as e:
                print(f"Error: {e}")

    def run_scan(self):
        """
        run the scan and return the results
        """

        self.console_printer.start(self.user)
        
        for provider in self.scanner.to_scan:
            self.queue.put((self.user, provider, False))

        threads = []
        
        for _ in range(5): 
            t = threading.Thread(target=self._worker, daemon=True)
            t.start()
            threads.append(t)

        self.queue.join()

        for t in threads:
            t.join()

        return self.results