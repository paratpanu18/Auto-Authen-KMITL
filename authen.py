#!/usr/bin/env python3
# PYTHON_ARGCOMPLETE_OK
import uuid
import argparse  
import json
import shutil
import getpass
import signal
import time
import requests
import sys
import os
import logging
from datetime import datetime

try:
    import argcomplete
    HAS_ARGCOMPLETE = True
except ImportError:
    HAS_ARGCOMPLETE = False

VERSION = "1.2.0"
CONFIG_DIR = os.path.expanduser("~/.config/kmitl-authen")
CONFIG_FILE = os.path.join(CONFIG_DIR, "config.json")
LOG_FILE = os.path.join(CONFIG_DIR, "authen.log")
PID_FILE = os.path.join(CONFIG_DIR, "authen.pid")

username = ''
password = ''
ipAddress = ''
acip = "10.252.13.10"

def get_mac_address() -> str:
    mac = uuid.getnode()
    mac_bytes = [(mac >> ele) & 0xff for ele in range(0, 8*6, 8)][::-1]
    return ':'.join(['{:02X}'.format(b) for b in mac_bytes])

def get_mac_address_raw() -> str:
    mac = uuid.getnode()
    mac_bytes = [(mac >> ele) & 0xff for ele in range(0, 8*6, 8)][::-1]
    return ''.join(['{:02x}'.format(b) for b in mac_bytes])

umac = get_mac_address_raw()
umac_formatted = get_mac_address()

time_repeat = 5*60 
max_login_attempt = 20

client_ip = ''
server_url = 'https://portal.kmitl.ac.th:19008/portalauth/login'
server_url_heartbeat = 'https://nani.csc.kmitl.ac.th/network-api/data/'
data = ''
agent = requests.session()


def setup_logging(to_console=True):
    """Setup logging to file and optionally console"""
    os.makedirs(CONFIG_DIR, exist_ok=True)
    
    handlers = [logging.FileHandler(LOG_FILE)]
    if to_console:
        handlers.append(logging.StreamHandler(sys.stdout))
    
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=handlers,
        force=True
    )
    return logging.getLogger('kmitl-authen')

logger = None  # Will be initialized in main or daemon


def signal_handler(sig, frame):
    """Handle Ctrl+C"""
    if logger:
        logger.info('Good bye!')
    else:
        print('Good bye!')
    cleanup_pid()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# determine terminal size
large_terminal = True
column, line = shutil.get_terminal_size()
if column < 108:
    large_terminal = False


def log_message(message, level='info'):
    """Log message to file and print to console"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    formatted = f"{timestamp} [x] {message}"
    
    if logger:
        if level == 'info':
            logger.info(message)
        elif level == 'error':
            logger.error(message)
        elif level == 'warning':
            logger.warning(message)
    else:
        print(formatted)


def print_format(*args, large_only=False, small_only=False, show_time=True, end='\n\n', **kwargs):
    if (large_only and not large_terminal) or (small_only and large_terminal):
        return

    message = ' '.join(str(arg) for arg in args)
    
    if large_terminal:
        print('\t', end='')
    if show_time:
        print(time.asctime(time.localtime()), '[x]', end=' ')
        if logger:
            logger.info(message.strip())
    print(*args, **kwargs, end=end)


def print_error(*args, **kwargs):
    message = ' '.join(str(arg) for arg in args)
    if logger:
        logger.error(message)
    print_format(*args, **kwargs, end='\n')


def get_config_dir():
    if not os.path.exists(CONFIG_DIR):
        os.makedirs(CONFIG_DIR)
    return CONFIG_DIR


def load_config():
    """Load configuration from file"""
    if not os.path.isfile(CONFIG_FILE):
        return None
    try:
        with open(CONFIG_FILE, 'r') as f:
            return json.load(f)
    except (json.JSONDecodeError, FileNotFoundError):
        return None


def save_config(config_data):
    """Save configuration to file"""
    get_config_dir()
    with open(CONFIG_FILE, 'w') as f:
        json.dump(config_data, f, indent=4)


def save_pid():
    """Save current process ID"""
    get_config_dir()
    with open(PID_FILE, 'w') as f:
        f.write(str(os.getpid()))


def cleanup_pid():
    """Remove PID file"""
    if os.path.exists(PID_FILE):
        try:
            os.remove(PID_FILE)
        except:
            pass


def get_running_pid():
    """Get PID of running instance"""
    if not os.path.exists(PID_FILE):
        return None
    try:
        with open(PID_FILE, 'r') as f:
            pid = int(f.read().strip())
        # Check if process is still running
        os.kill(pid, 0)
        return pid
    except (ValueError, ProcessLookupError, PermissionError, FileNotFoundError):
        return None


def daemonize():
    """Fork the process to run in background"""
    # First fork
    try:
        pid = os.fork()
        if pid > 0:
            # Parent exits
            sys.exit(0)
    except OSError as e:
        print(f"Fork #1 failed: {e}")
        sys.exit(1)
    
    # Decouple from parent environment
    os.chdir('/')
    os.setsid()
    os.umask(0)
    
    # Second fork
    try:
        pid = os.fork()
        if pid > 0:
            # Parent exits
            sys.exit(0)
    except OSError as e:
        print(f"Fork #2 failed: {e}")
        sys.exit(1)
    
    # Redirect standard file descriptors
    sys.stdout.flush()
    sys.stderr.flush()
    
    # Redirect stdin, stdout, stderr to /dev/null
    with open('/dev/null', 'r') as devnull:
        os.dup2(devnull.fileno(), sys.stdin.fileno())
    with open(LOG_FILE, 'a') as log:
        os.dup2(log.fileno(), sys.stdout.fileno())
        os.dup2(log.fileno(), sys.stderr.fileno())


def init():
    logo = '''
         ██████╗███████╗    ██╗  ██╗ ██████╗ ██╗   ██╗███████╗███████╗
        ██╔════╝██╔════╝    ██║  ██║██╔═══██╗██║   ██║██╔════╝██╔════╝
        ██║     █████╗      ███████║██║   ██║██║   ██║███████╗█████╗  
        ██║     ██╔══╝      ██╔══██║██║   ██║██║   ██║╚════██║██╔══╝  
        ╚██████╗███████╗    ██║  ██║╚██████╔╝╚██████╔╝███████║███████╗
         ╚═════╝╚══════╝    ╚═╝  ╚═╝ ╚═════╝  ╚═════╝ ╚══════╝╚══════╝
                                                                      
                        https://github.com/CE-HOUSE                   
        
'''
    print_format(logo, large_only=True, show_time=False)
    print_format('CE-HOUSE', show_time=True)


def login():
    global data
    try:
        url = server_url
        content = agent.post(url, params={
            'userName': username, 
            'userPass': password,
            'uaddress': ipAddress,
            'umac': umac,
            'agreed': 1,
            'acip': acip,
            'authType': 1
        })
    except requests.exceptions.RequestException:
        print_format('Connection lost...', show_time=True, end='\n')
        return False
    
    try:
        content_dict = json.loads(content.text)
        data = content_dict['data']
    except (json.JSONDecodeError, KeyError):
        pass

    if content.status_code != 200:
        print_format('Error! Something went wrong (maybe wrong username and/or password?)...')
        return False
    return True


def heartbeat() -> tuple:
    try:
        content = agent.post(server_url_heartbeat, params={
            'username': username,
            'os': "Chrome v116.0.5845.141 on Windows 10 64-bit",
            'speed': 1.29,
            'newauth': 1
        })
    except requests.exceptions.RequestException:
        print_format('Connection lost...')
        time.sleep(1)
        return False, False
    
    if content.status_code == 200:
        print_format('Heartbeat OK...')
        return True, True
    else:
        print_format('Heartbeat failed...')
        return True, False


def check_connection() -> tuple:
    try:
        content = requests.get('http://detectportal.firefox.com/success.txt', timeout=5)
    except requests.exceptions.RequestException:
        return False, False
    if content.text == 'success\n':
        return True, True
    return True, False


def start_auth():
    login_attempt = 0
    printed_logged_in = False
    printed_lost = False
    reset_timer = time.time() + (8*60*60)
    login()
    
    while True:
        remain_to_reset = reset_timer - time.time()
        connection, internet = check_connection()
        
        if remain_to_reset <= 480:
            return
        
        if connection and internet:
            if not printed_logged_in:
                print('', end='\n')
                print_format('Welcome {}!'.format(username), end='\n')
                print_format('Your IP:', ipAddress, end='\n')
                print_format('Heartbeat every', time_repeat, 'seconds', end='\n')
                print_format('Max login attempt:', max_login_attempt)
                print_format('''
         ██████╗ ██████╗ ███╗   ██╗███╗   ██╗███████╗ ██████╗████████╗███████╗██████╗ 
        ██╔════╝██╔═══██╗████╗  ██║████╗  ██║██╔════╝██╔════╝╚══██╔══╝██╔════╝██╔══██╗
        ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║█████╗  ██║        ██║   █████╗  ██║  ██║
        ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██╔══╝  ██║        ██║   ██╔══╝  ██║  ██║
        ╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║███████╗╚██████╗   ██║   ███████╗██████╔╝
         ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚══════╝ ╚═════╝   ╚═╝   ╚══════╝╚═════╝ 
''', show_time=False)
                printed_logged_in = True
                printed_lost = False
            
            time.sleep(time_repeat)
            connection, heatdone = heartbeat()
            
            if not connection and not heatdone:
                return
            elif connection and not heatdone:
                login()
        
        elif connection and not internet:
            if login_attempt == max_login_attempt:
                print_error('Error! Please recheck your username and password...')
            login()
            login_attempt += 1
        
        else:
            if not printed_lost:
                print('', end='\n')
                print_format('''
        ██╗      ██████╗ ███████╗████████╗
        ██║     ██╔═══██╗██╔════╝╚══██╔══╝
        ██║     ██║   ██║███████╗   ██║   
        ██║     ██║   ██║╚════██║   ██║   
        ███████╗╚██████╔╝███████║   ██║   
        ╚══════╝ ╚═════╝ ╚══════╝   ╚═╝   
''', show_time=False)
                printed_lost = True
                printed_logged_in = False
            
            if login_attempt > max_login_attempt:
                print_error("Login attempt exceed maximum")
                break
            
            login()
            login_attempt += 1
            time.sleep(10)


def print_table(title, rows):
    """Print a simple ASCII table"""
    if not rows:
        return
    
    # Calculate column widths
    col1_width = max(len(str(row[0])) for row in rows) + 2
    col2_width = max(len(str(row[1])) for row in rows) + 2
    total_width = col1_width + col2_width + 3
    
    # Print table
    print()
    print(f"=== {title} ===")
    print("-" * total_width)
    for row in rows:
        print(f" {row[0]:<{col1_width}} | {row[1]:<{col2_width}}")
    print("-" * total_width)


# ==================== CLI Commands ====================

def cmd_start(args):
    """Start the authentication process"""
    global username, password, ipAddress, max_login_attempt, logger
    
    # Check if already running
    running_pid = get_running_pid()
    if running_pid:
        print(f"Warning: Another instance is already running (PID: {running_pid})")
        confirm = input("Start anyway? (y/N): ").lower()
        if confirm not in ['y', 'yes']:
            return
    
    config = load_config()
    ram_password = None
    
    if config is None:
        print("No configuration found. Run 'kmitl-authen config create' first.")
        try:
            to_create = input('Do you want to create a new config now? (Y/n): ').lower()
            if to_create not in ['n', 'no']:
                ram_password = cmd_config_create(args)
                config = load_config()
            else:
                sys.exit(1)
        except EOFError:
            print('\nGood bye!')
            sys.exit(0)
    
    if config:
        username = config.get('username', '')
        password = config.get('password', '')
        ipAddress = config.get('ipAddress', '')
        
        # Check if password should be asked (RAM-only mode)
        store_password = config.get('store_password', True)
        if not store_password and password == '':
            # Use password from config creation if available
            if ram_password:
                password = ram_password
            else:
                print("\n--- Stored Configuration ---")
                print(f"Username:      {username}")
                print(f"IP Address:    {ipAddress}")
                print(f"Password Mode: RAM-only (secure)")
                print()
                password = getpass.getpass('Enter your password: ')
    
    # Override with command line args
    if args.username:
        username = args.username
    if args.password:
        password = args.password
    if args.ipAddress:
        ipAddress = args.ipAddress
    if args.max_attempt:
        max_login_attempt = args.max_attempt
    
    # Validate
    if not username or not password or not ipAddress:
        print('Error! Please provide username, password, and IP address.')
        print("Run 'kmitl-authen config create' to set up your configuration.")
        sys.exit(1)
    
    # Check if running in foreground mode (daemon is default)
    foreground_mode = args.foreground if hasattr(args, 'foreground') and args.foreground else False
    
    if foreground_mode:
        # Foreground mode
        logger = setup_logging(to_console=True)
        save_pid()
        
        try:
            init()
            print_format('Logging in with username \'{}\'...'.format(username))
            
            while True:
                start_auth()
        finally:
            cleanup_pid()
    else:
        # Daemon mode (default)
        print(f"Starting kmitl-authen in background...")
        print(f"  Username: {username}")
        print(f"  IP: {ipAddress}")
        print(f"  Log file: {LOG_FILE}")
        print()
        print("Use 'kmitl-authen status' to check status")
        print("Use 'kmitl-authen logs -f' to follow logs")
        print("Use 'kmitl-authen stop' to stop")
        
        # Daemonize before saving PID
        daemonize()
        
        # Now in daemon process
        logger = setup_logging(to_console=False)
        save_pid()
        
        try:
            logger.info(f"Started daemon for user {username}")
            while True:
                start_auth()
        except Exception as e:
            logger.error(f"Daemon error: {e}")
        finally:
            cleanup_pid()


def cmd_status(args):
    """Show current connection status"""
    print()
    
    # Check connection
    print("Checking connection...")
    connection, internet = check_connection()
    
    # Connection status
    status_rows = []
    if not connection:
        status_rows.append(("Network", "[X] No connection"))
        status_rows.append(("Authentication", "N/A"))
    elif connection and not internet:
        status_rows.append(("Network", "[!] Connected"))
        status_rows.append(("Authentication", "[X] Not authenticated (captive portal)"))
    else:
        status_rows.append(("Network", "[OK] Connected"))
        status_rows.append(("Authentication", "[OK] Authenticated"))
    
    # Check if service is running
    running_pid = get_running_pid()
    if running_pid:
        status_rows.append(("Service", f"[OK] Running (PID: {running_pid})"))
    else:
        status_rows.append(("Service", "[!] Not running"))
    
    print_table("Connection Status", status_rows)
    
    # Configuration
    config = load_config()
    config_rows = []
    
    if config:
        config_rows.append(("Config File", CONFIG_FILE))
        config_rows.append(("Username", config.get('username', 'N/A')))
        config_rows.append(("IP Address", config.get('ipAddress', 'N/A')))
        store_pwd = config.get('store_password', True)
        config_rows.append(("Password Storage", "File" if store_pwd else "RAM only (secure)"))
    else:
        config_rows.append(("Status", "No configuration found"))
    
    config_rows.append(("MAC Address", umac_formatted))
    config_rows.append(("Log File", LOG_FILE))
    
    print_table("Configuration", config_rows)
    print()


def cmd_logs(args):
    """Follow the log output"""
    if not os.path.exists(LOG_FILE):
        print("No log file found.")
        print(f"Log file location: {LOG_FILE}")
        return
    
    lines = args.lines if hasattr(args, 'lines') and args.lines else 20
    
    print(f"Showing last {lines} lines from {LOG_FILE}")
    print("Press Ctrl+C to exit\n")
    
    if args.follow:
        # Follow mode - tail -f style
        import subprocess
        try:
            subprocess.run(['tail', '-n', str(lines), '-f', LOG_FILE])
        except KeyboardInterrupt:
            print("\nStopped following logs.")
        except FileNotFoundError:
            # tail not available, fallback
            print("'tail' command not found. Showing last lines only:")
            with open(LOG_FILE, 'r') as f:
                for line in f.readlines()[-lines:]:
                    print(line, end='')
    else:
        # Just show last N lines
        try:
            with open(LOG_FILE, 'r') as f:
                all_lines = f.readlines()
                for line in all_lines[-lines:]:
                    print(line, end='')
        except FileNotFoundError:
            print("Log file not found.")


def cmd_stop(args):
    """Stop the running authentication service"""
    pid = get_running_pid()
    if pid is None:
        print("No running instance found.")
        return
    
    print(f"Stopping kmitl-authen (PID: {pid})...")
    try:
        os.kill(pid, signal.SIGTERM)
        time.sleep(1)
        # Check if still running
        try:
            os.kill(pid, 0)
            # Still running, force kill
            os.kill(pid, signal.SIGKILL)
            time.sleep(0.5)
        except ProcessLookupError:
            pass
        cleanup_pid()
        print("[OK] Stopped successfully.")
    except ProcessLookupError:
        cleanup_pid()
        print("Process was not running.")
    except PermissionError:
        print("Permission denied. Try with sudo.")


def cmd_config_show(args):
    """Show current configuration"""
    config = load_config()
    
    if config is None:
        print("No configuration found.")
        print(f"Config file location: {CONFIG_FILE}")
        return
    
    # Main config
    rows = [
        ("Config File", CONFIG_FILE),
        ("Username", config.get('username', 'N/A')),
        ("IP Address", config.get('ipAddress', 'N/A')),
    ]
    
    store_pwd = config.get('store_password', True)
    if store_pwd:
        rows.append(("Password", "******** (stored in file)"))
    else:
        rows.append(("Password", "RAM-only mode (will ask each time)"))
    
    rows.append(("Password Storage", "File" if store_pwd else "RAM only"))
    
    print_table("Current Configuration", rows)
    
    # System info
    sys_rows = [
        ("MAC Address", umac_formatted),
        ("Log File", LOG_FILE),
        ("PID File", PID_FILE),
    ]
    print_table("System Information", sys_rows)
    print()


def cmd_config_create(args):
    """Create new configuration. Returns password if RAM-only mode."""
    print()
    print("=== KMITL Authentication Setup ===")
    print()
    
    # Check if config exists
    existing = load_config()
    if existing:
        confirm = input("Configuration already exists. Overwrite? (y/N): ").lower()
        if confirm not in ['y', 'yes']:
            print("Cancelled.")
            return None
    
    print('\n--- Password Storage Options ---')
    print('[1] Store password in config file (convenient but less secure)')
    print('[2] Keep password in RAM only (more secure, will ask each time)')
    
    while True:
        storage_choice = input('\nChoose option (1 or 2): ').strip()
        if storage_choice in ['1', '2']:
            break
        print('Invalid choice. Please enter 1 or 2.')
    
    store_password_in_file = (storage_choice == '1')
    
    input_username = input('\nYour username (student ID, without @kmitl.ac.th): ')
    input_password = getpass.getpass('Your password: ')
    input_ip = input('Your Public IP Address: ')
    
    config_data = {}
    if input_username:
        config_data['username'] = input_username
    if input_password and store_password_in_file:
        config_data['password'] = input_password
    if input_ip:
        config_data['ipAddress'] = input_ip
    
    config_data['store_password'] = store_password_in_file
    
    save_config(config_data)
    
    print()
    print(f"[OK] Configuration saved to: {CONFIG_FILE}")
    if store_password_in_file:
        print("     Password is stored in the config file.")
    else:
        print("     Password will be asked each time (RAM-only mode).")
    print()
    
    # Return password for immediate use if RAM-only mode
    if not store_password_in_file:
        return input_password
    return None


def cmd_config_remove(args):
    """Remove configuration file"""
    if not os.path.isfile(CONFIG_FILE):
        print("No configuration file found.")
        return
    
    confirm = input(f"Remove configuration file at {CONFIG_FILE}? (y/N): ").lower()
    if confirm in ['y', 'yes']:
        os.remove(CONFIG_FILE)
        print("[OK] Configuration removed.")
    else:
        print("Cancelled.")


def cmd_config_edit(args):
    """Edit existing configuration"""
    config = load_config()
    if config is None:
        print("No configuration found. Creating new one...")
        cmd_config_create(args)
        return
    
    print()
    print("=== Edit Configuration ===")
    print("Press Enter to keep current value.\n")
    
    # Username
    current_user = config.get('username', '')
    new_user = input(f"Username [{current_user}]: ").strip()
    if new_user:
        config['username'] = new_user
    
    # IP Address
    current_ip = config.get('ipAddress', '')
    new_ip = input(f"IP Address [{current_ip}]: ").strip()
    if new_ip:
        config['ipAddress'] = new_ip
    
    # Password storage preference
    current_store = config.get('store_password', True)
    current_mode = "file" if current_store else "RAM-only"
    print(f"\nCurrent password storage mode: {current_mode}")
    change_mode = input("Change password storage mode? (y/N): ").lower()
    
    if change_mode in ['y', 'yes']:
        print('[1] Store password in config file')
        print('[2] Keep password in RAM only')
        while True:
            choice = input('Choose option (1 or 2): ').strip()
            if choice in ['1', '2']:
                break
            print('Invalid choice.')
        config['store_password'] = (choice == '1')
        
        # If switching to RAM-only, remove password from config
        if choice == '2':
            config.pop('password', None)
    
    # Password
    change_pwd = input("\nChange password? (y/N): ").lower()
    if change_pwd in ['y', 'yes']:
        new_pwd = getpass.getpass("New password: ")
        if new_pwd:
            if config.get('store_password', True):
                config['password'] = new_pwd
            else:
                config.pop('password', None)
    
    save_config(config)
    print("\n[OK] Configuration updated.")


def cmd_config(args):
    """Handle config subcommands"""
    if hasattr(args, 'config_command') and args.config_command:
        pass
    else:
        cmd_config_show(args)


def cmd_completion(args):
    """Show how to enable shell completion"""
    print()
    print("=== Shell Completion Setup ===")
    print()
    
    print("For Bash:")
    print('  Add this to your ~/.bashrc:')
    print('  eval "$(register-python-argcomplete kmitl-authen)"')
    print()
    
    print("For Zsh:")
    print('  Add this to your ~/.zshrc:')
    print('  autoload -U bashcompinit')
    print('  bashcompinit')
    print('  eval "$(register-python-argcomplete kmitl-authen)"')
    print()
    
    print("For Fish:")
    print('  Run:')
    print('  register-python-argcomplete --shell fish kmitl-authen > ~/.config/fish/completions/kmitl-authen.fish')
    print()
    
    print("Note: You need to install argcomplete first:")
    print("  pip install argcomplete")
    print()
    
    if not HAS_ARGCOMPLETE:
        print("[!] argcomplete is not installed. Install it for tab completion support.")
    else:
        print("[OK] argcomplete is installed.")
    print()


def main():
    global logger
    
    # Main parser
    parser = argparse.ArgumentParser(
        prog='kmitl-authen',
        description='KMITL Network Auto-Authentication',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  kmitl-authen                    Start authentication (background/daemon)
  kmitl-authen start              Start authentication (background/daemon)
  kmitl-authen start -f           Start authentication (foreground)
  kmitl-authen status             Check connection status
  kmitl-authen stop               Stop running instance
  kmitl-authen logs               Show recent logs
  kmitl-authen logs -f            Follow logs in real-time
  kmitl-authen config show        Show configuration
  kmitl-authen config create      Create new configuration
  kmitl-authen config edit        Edit configuration
  kmitl-authen config remove      Remove configuration
  kmitl-authen completion         Show shell completion setup
        '''
    )
    parser.add_argument('--version', action='version', version=f'%(prog)s {VERSION}')
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Start command
    start_parser = subparsers.add_parser('start', help='Start authentication (daemon by default)')
    start_parser.add_argument('-f', '--foreground', action='store_true', 
                              help='Run in foreground instead of daemon mode')
    start_parser.add_argument('-u', '--username', dest='username', help='Username')
    start_parser.add_argument('-p', '--password', dest='password', help='Password')
    start_parser.add_argument('-ip', '--ip-address', dest='ipAddress', help='IP Address')
    start_parser.add_argument('--max-attempt', dest='max_attempt', type=int,
                              help=f'Maximum login attempts (default: {max_login_attempt})')
    start_parser.set_defaults(func=cmd_start)
    
    # Status command
    status_parser = subparsers.add_parser('status', help='Show connection status')
    status_parser.set_defaults(func=cmd_status)
    
    # Stop command
    stop_parser = subparsers.add_parser('stop', help='Stop running instance')
    stop_parser.set_defaults(func=cmd_stop)
    
    # Logs command
    logs_parser = subparsers.add_parser('logs', help='Show authentication logs')
    logs_parser.add_argument('-f', '--follow', action='store_true', help='Follow log output')
    logs_parser.add_argument('-n', '--lines', type=int, default=20, help='Number of lines to show (default: 20)')
    logs_parser.set_defaults(func=cmd_logs)
    
    # Config command with subcommands
    config_parser = subparsers.add_parser('config', help='Configuration management')
    config_subparsers = config_parser.add_subparsers(dest='config_command')
    
    config_show = config_subparsers.add_parser('show', help='Show current configuration')
    config_show.set_defaults(func=cmd_config_show)
    
    config_create = config_subparsers.add_parser('create', help='Create new configuration')
    config_create.set_defaults(func=cmd_config_create)
    
    config_remove = config_subparsers.add_parser('remove', help='Remove configuration')
    config_remove.set_defaults(func=cmd_config_remove)
    
    config_edit = config_subparsers.add_parser('edit', help='Edit configuration')
    config_edit.set_defaults(func=cmd_config_edit)
    
    config_parser.set_defaults(func=cmd_config)
    
    # Completion command
    completion_parser = subparsers.add_parser('completion', help='Show shell completion setup instructions')
    completion_parser.set_defaults(func=cmd_completion)
    
    # Enable argcomplete if available
    if HAS_ARGCOMPLETE:
        argcomplete.autocomplete(parser)
    
    # Parse arguments
    args = parser.parse_args()
    
    # Default to start if no command given
    if args.command is None:
        args.username = None
        args.password = None
        args.ipAddress = None
        args.max_attempt = None
        args.foreground = False
        cmd_start(args)
    elif hasattr(args, 'func'):
        args.func(args)
    else:
        parser.print_help()


if __name__ == '__main__':
    main()