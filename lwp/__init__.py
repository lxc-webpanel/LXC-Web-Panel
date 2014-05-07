import sys
sys.path.append('../')
from lxclite import exists, stopped, ContainerDoesntExists
import subprocess
import os
import platform
import time
import re

from io import StringIO

try:
    from urllib.request import urlopen
except ImportError:
    from urllib2 import urlopen

try:
    import configparser
except ImportError:
    import ConfigParser as configparser

class CalledProcessError(Exception): pass

cgroup = {}
cgroup['type'] = 'lxc.network.type'
cgroup['link'] = 'lxc.network.link'
cgroup['flags'] = 'lxc.network.flags'
cgroup['hwaddr'] = 'lxc.network.hwaddr'
cgroup['rootfs'] = 'lxc.rootfs'
cgroup['utsname'] = 'lxc.utsname'
cgroup['arch'] = 'lxc.arch'
cgroup['ipv4'] = 'lxc.network.ipv4'
cgroup['memlimit'] = 'lxc.cgroup.memory.limit_in_bytes'
cgroup['swlimit'] = 'lxc.cgroup.memory.memsw.limit_in_bytes'
cgroup['cpus'] = 'lxc.cgroup.cpuset.cpus'
cgroup['shares'] = 'lxc.cgroup.cpu.shares'
cgroup['deny'] = 'lxc.cgroup.devices.deny'
cgroup['allow'] = 'lxc.cgroup.devices.allow'


def FakeSection(fp):
    content = u"[DEFAULT]\n%s" % fp.read()

    return StringIO(content)


def DelSection(filename=None):
    if filename:
        load = open(filename, 'r')
        read = load.readlines()
        load.close()
        i = 0
        while i < len(read):
            if '[DEFAULT]' in read[i]:
                del read[i]
                break
        load = open(filename, 'w')
        load.writelines(read)
        load.close()


def file_exist(filename):
    '''
    checks if a given file exist or not
    '''
    try:
        with open(filename) as f:
            f.close()
            return True
    except IOError:
        return False


def ls_auto():
    '''
    returns a list of autostart containers
    '''
    try:
        auto_list = os.listdir('/etc/lxc/auto/')
    except OSError:
        auto_list = []
    return auto_list


def memory_usage(name):
    '''
    returns memory usage in MB
    '''
    if not exists(name):
        raise ContainerDoesntExists("The container (%s) does not exist!" % name)
    if name in stopped():
        return 0
    cmd = ['lxc-cgroup -n %s memory.usage_in_bytes' % name]
    try:
        out = subprocess.check_output(cmd, shell=True).splitlines()
    except:
        return 0
    return int(out[0])/1024/1024


def host_memory_usage():
    '''
    returns a dict of host memory usage values
                    {'percent': int((used/total)*100),
                    'percent_cached':int((cached/total)*100),
                    'used': int(used/1024),
                    'total': int(total/1024)}
    '''
    out = open('/proc/meminfo')
    for line in out:
        if 'MemTotal:' == line.split()[0]:
            split = line.split()
            total = float(split[1])
        if 'MemFree:' == line.split()[0]:
            split = line.split()
            free = float(split[1])
        if 'Buffers:' == line.split()[0]:
            split = line.split()
            buffers = float(split[1])
        if 'Cached:' == line.split()[0]:
            split = line.split()
            cached = float(split[1])
    out.close()
    used = (total - (free + buffers + cached))
    return {'percent': int((used/total)*100),
            'percent_cached': int(((cached)/total)*100),
            'used': int(used/1024),
            'total': int(total/1024)}


def host_cpu_percent():
    '''
    returns CPU usage in percent
    '''
    f = open('/proc/stat', 'r')
    line = f.readlines()[0]
    data = line.split()
    previdle = float(data[4])
    prevtotal = float(data[1]) + float(data[2]) + float(data[3]) + float(data[4])
    f.close()
    time.sleep(0.1)
    f = open('/proc/stat', 'r')
    line = f.readlines()[0]
    data = line.split()
    idle = float(data[4])
    total = float(data[1]) + float(data[2]) + float(data[3]) + float(data[4])
    f.close()
    intervaltotal = total - prevtotal
    percent = 100 * (intervaltotal - (idle - previdle)) / intervaltotal
    return str('%.1f' % percent)


def host_disk_usage(partition=None):
    '''
    returns a dict of disk usage values
                    {'total': usage[1],
                    'used': usage[2],
                    'free': usage[3],
                    'percent': usage[4]}
    '''
    if not partition:
        partition = '/'
    usage = subprocess.check_output(['df -h %s' % partition], shell=True).split('\n')[1].split()
    return {'total': usage[1],
            'used': usage[2],
            'free': usage[3],
            'percent': usage[4]}


def host_uptime():
    '''
    returns a dict of the system uptime
            {'day': days,
            'time': '%d:%02d' % (hours,minutes)}
    '''
    f = open('/proc/uptime')
    uptime = int(f.readlines()[0].split('.')[0])
    minutes = uptime / 60 % 60
    hours = uptime / 60 / 60 % 24
    days = uptime / 60 / 60 / 24
    f.close()
    return {'day': days,
            'time': '%d:%02d' % (hours, minutes)}


def check_ubuntu():
    '''
    return the System version
    '''
    dist = '%s %s' % (platform.linux_distribution()[0], platform.linux_distribution()[1])
    return dist


def get_templates_list():
    '''
    returns a sorted lxc templates list
    '''
    templates = []
    path = None

    try:
        path = os.listdir('/usr/share/lxc/templates')
    except:
        path = os.listdir('/usr/lib/lxc/templates') 

    if path:
        for line in path:
                templates.append(line.replace('lxc-', ''))

    return sorted(templates)


def check_version():
    '''
    returns latest LWP version (dict with current and latest)
    '''
    f = open('version')
    current = float(f.read())
    f.close()
    latest = float(urlopen('http://lxc-webpanel.github.com/version').read())
    return {'current':current,
            'latest':latest}


def get_net_settings():
    '''
    returns a dict of all known settings for LXC networking
    '''
    filename = '/etc/default/lxc-net'
    if not file_exist(filename):
        filename = '/etc/default/lxc'
    if not file_exist(filename):
        return False
    config = configparser.SafeConfigParser()
    cfg = {}
    config.readfp(FakeSection(open(filename)))
    cfg['use'] = config.get('DEFAULT', 'USE_LXC_BRIDGE').strip('"')
    cfg['bridge'] = config.get('DEFAULT', 'LXC_BRIDGE').strip('"')
    cfg['address'] = config.get('DEFAULT', 'LXC_ADDR').strip('"')
    cfg['netmask'] = config.get('DEFAULT', 'LXC_NETMASK').strip('"')
    cfg['network'] = config.get('DEFAULT', 'LXC_NETWORK').strip('"')
    cfg['range'] = config.get('DEFAULT', 'LXC_DHCP_RANGE').strip('"')
    cfg['max'] = config.get('DEFAULT', 'LXC_DHCP_MAX').strip('"')
    return cfg


def get_container_settings(name):
    '''
    returns a dict of all utils settings for a container
    '''
    filename = '/var/lib/lxc/%s/config' % name
    if not file_exist(filename):
        return False
    config = configparser.SafeConfigParser()
    cfg = {}
    config.readfp(FakeSection(open(filename)))
    try:
        cfg['type'] = config.get('DEFAULT', cgroup['type'])
    except configparser.NoOptionError:
        cfg['type'] = ''
    try:
        cfg['link'] = config.get('DEFAULT', cgroup['link'])
    except configparser.NoOptionError:
        cfg['link'] = ''
    try:
        cfg['flags'] = config.get('DEFAULT', cgroup['flags'])
    except configparser.NoOptionError:
        cfg['flags'] = ''
    try:
        cfg['hwaddr'] = config.get('DEFAULT', cgroup['hwaddr'])
    except configparser.NoOptionError:
        cfg['hwaddr'] = ''
    try:
        cfg['rootfs'] = config.get('DEFAULT', cgroup['rootfs'])
    except configparser.NoOptionError:
        cfg['rootfs'] = ''
    try:
        cfg['utsname'] = config.get('DEFAULT', cgroup['utsname'])
    except configparser.NoOptionError:
        cfg['utsname'] = ''
    try:
        cfg['arch'] = config.get('DEFAULT', cgroup['arch'])
    except configparser.NoOptionError:
        cfg['arch'] = ''
    try:
        cfg['ipv4'] = config.get('DEFAULT', cgroup['ipv4'])
    except configparser.NoOptionError:
        cfg['ipv4'] = ''
    try:
        cfg['memlimit'] = re.sub(r'[a-zA-Z]', '', config.get('DEFAULT', cgroup['memlimit']))
    except configparser.NoOptionError:
        cfg['memlimit'] = ''
    try:
        cfg['swlimit'] = re.sub(r'[a-zA-Z]', '', config.get('DEFAULT', cgroup['swlimit']))
    except configparser.NoOptionError:
        cfg['swlimit'] = ''
    try:
        cfg['cpus'] = config.get('DEFAULT', cgroup['cpus'])
    except configparser.NoOptionError:
        cfg['cpus'] = ''
    try:
        cfg['shares'] = config.get('DEFAULT', cgroup['shares'])
    except configparser.NoOptionError:
        cfg['shares'] = ''

    if '%s.conf' % name in ls_auto():
        cfg['auto'] = True
    else:
        cfg['auto'] = False

    return cfg


def push_net_value(key, value, filename='/etc/default/lxc'):
    '''
    replace a var in the lxc-net config file
    '''
    if filename:
        config = configparser.RawConfigParser()
        config.readfp(FakeSection(open(filename)))
        if not value:
            config.remove_option('DEFAULT', key)
        else:
            config.set('DEFAULT', key, value)

        with open(filename, 'wb') as configfile:
            config.write(configfile)

        DelSection(filename=filename)

        load = open(filename, 'r')
        read = load.readlines()
        load.close()
        i = 0
        while i < len(read):
            if ' = ' in read[i]:
                split = read[i].split(' = ')
                split[1] = split[1].strip('\n')
                if '\"' in split[1]:
                    read[i] = '%s=%s\n' % (split[0].upper(), split[1])
                else:
                    read[i] = '%s=\"%s\"\n' % (split[0].upper(), split[1])
            i += 1
        load = open(filename, 'w')
        load.writelines(read)
        load.close()


def push_config_value(key, value, container=None):
    '''
    replace a var in a container config file
    '''

    def save_cgroup_devices(filename=None):
        '''
        returns multiple values (lxc.cgroup.devices.deny and lxc.cgroup.devices.allow) in a list.
        because configparser cannot make this...
        '''
        if filename:
            values = []
            i = 0

            load = open(filename, 'r')
            read = load.readlines()
            load.close()

            while i < len(read):
                if not read[i].startswith('#') and re.match('lxc.cgroup.devices.deny|lxc.cgroup.devices.allow', read[i]):
                    values.append(read[i])
                i += 1
            return values

    if container:
        filename = '/var/lib/lxc/%s/config' % container
        save = save_cgroup_devices(filename=filename)

        config = configparser.RawConfigParser()
        config.readfp(FakeSection(open(filename)))
        if not value:
            config.remove_option('DEFAULT', key)
        elif key == cgroup['memlimit'] or key == cgroup['swlimit'] and value != False:
            config.set('DEFAULT', key, '%sM' % value)
        else:
            config.set('DEFAULT', key, value)

        # Bugfix (can't duplicate keys with config parser)
        if config.has_option('DEFAULT', cgroup['deny']) or config.has_option('DEFAULT', cgroup['allow']):
            config.remove_option('DEFAULT', cgroup['deny'])
            config.remove_option('DEFAULT', cgroup['allow'])

        with open(filename, 'wb') as configfile:
            config.write(configfile)

        DelSection(filename=filename)

        with open(filename, "a") as configfile:
            configfile.writelines(save)


def net_restart():
    '''
    restarts LXC networking
    '''
    cmd = ['/usr/sbin/service lxc-net restart']
    try:
        subprocess.check_call(cmd, shell=True)
        return 0
    except CalledProcessError:
        return 1
