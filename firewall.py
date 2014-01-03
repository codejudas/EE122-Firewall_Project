#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries, though.
import socket
import struct

class Firewall:

    def __init__(self, config, timer, iface_int, iface_ext):
        self.timer = timer
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        #Load the firewall rules (from rule_filename) here.
        filename = config['rule']
        rule_src = open(filename, 'r')
        self.rules = []
        self.http_domain_rules = [] #holds log rules for domain names
        self.http_ip_rules = [] #holds log rules for pure ip addresses
        line = rule_src.readline()
        while line != "": #read entire file
    	    if (line[0] != '%') and (line != '\n'): #ignore comments
		    	line = line[:-1] #strip newline character
		    	line = line.lower() #convert string to lowercase
		    	entry = line.split()
		    	if entry[0] == 'log':
		    	    if self._is_ip_addr(entry[2]):
		    	        self.http_ip_rules.append(entry[2])
		    	    else:
		    	        labels = entry[2].split('.')
		    	        self.http_domain_rules.append(labels)
		    	else:
		    	    self.rules.append(entry)
            line = rule_src.readline()
        rule_src.close()
        print 'firewall rules:'+str(self.rules)
        print 'http rules:'+str([self.http_ip_rules, self.http_domain_rules])
        

        #Load the GeoIP DB ('geoipdb.txt') as well.
        country_src = open('geoipdb.txt', 'r')
        self.countries = []
        line = country_src.readline()
        while line != "":
    	    if line != '\n': #ignore empty lines
    	    	line = line[:-1] #strip newline character
    	    	line = line.lower()
    	    	entry = line.split()
    	    	self.countries.append(entry)
    	    line = country_src.readline()
        country_src.close()
        
        #setup http connection states
        self.connections = [] #for each elem: [0] is 4 elem tuple identifying connection, [1] is int status, [2] is tuple (ext_seq, int_seq)[3] is string buffer,
        self.transactions = [] #list of the fields to be logged in a transaction


    def handle_timer(self):
        # TODO: For the timer feature, refer to bypass.py
        pass

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        error = False
        print('\n-------------')#make output easier to read
        try:
            protocol = struct.unpack('!B',pkt[9])[0] #! for network order, B because 1 byte long
            ipid = struct.unpack('!H', pkt[4:6])[0]    # IP identifier (big endian)
            header_len = struct.unpack('!B',pkt[0])[0] & 0b00001111 #get length of header in 4-byte pieces
            total_len = struct.unpack('!H', pkt[2:4])[0] #total length of packet including header and data
        except IndexError:
            print('error reading ip header, packet dropped')
            error = True
            
        if (error == False) and (header_len*4 < 20):
            print 'IP header too short, packet dropped'
            error = True
            
        if (error == False) and (total_len > len(pkt)):
            print('truncated packet dropped')
            error = True
        
        if not error:
            src_ip_net = pkt[12:16] #network binary
            src_ip_str = socket.inet_ntoa(src_ip_net) #string x.x.x.x
            src_ip = struct.unpack('!L', src_ip_net)[0] #get numerical rep of ip
            dst_ip_net = pkt[16:20]
            dst_ip_str = socket.inet_ntoa(dst_ip_net)
            dst_ip = struct.unpack('!L', dst_ip_net)[0]
            ip_id = pkt[4:6]

            if pkt_dir == PKT_DIR_INCOMING:
                dir_str = 'incoming'
            else:
                dir_str = 'outgoing'
        
            allow = None #decides whether to allow the packet or not
            protocol_str = 'Other'
	
            if protocol == 1: #ICMP packet
                icmp_start = header_len*4
                try:
                    icmp_type = struct.unpack('!B', pkt[icmp_start])[0]
                    protocol_str = 'ICMP(%d)' % icmp_type
	        
                    if pkt_dir == PKT_DIR_INCOMING:
    	                allow = self._match_rule('icmp', src_ip, icmp_type, False)
    	            else:
    	                allow = self._match_rule('icmp', dst_ip, icmp_type, False)
    	                
    	        except IndexError:
    	            print('dropped unreadable ICMP packet')
    	            allow = False
		        
            elif protocol == 6: #TCP packet
    	        tcp_start = header_len*4
    	        try:
    	            src_port = struct.unpack('!H', pkt[tcp_start:tcp_start+2])[0] #get and unpack src_port of TCP header
    	            dst_port = struct.unpack('!H', pkt[tcp_start+2:tcp_start+4])[0]
    	            seqno = struct.unpack('!I', pkt[tcp_start+4:tcp_start+8])[0]
    	            flags = struct.unpack('!B', pkt[tcp_start+13:tcp_start+14])[0]
                    ack_set = ((flags & 0x10) == 0x10)
    	            if ack_set: #ack bit is set
    	                ack = struct.unpack('!I', pkt[tcp_start+8:tcp_start+12])[0]
    	            else:
                        ack = None
    	            syn_set = ((flags & 0x02) == 0x02) #True if syn bit is set
                    fin_set = ((flags & 0x01) == 0x01) #True if fin bit is set
                    rst_set = ((flags & 0x04) == 0x04)
    	            tcp_length = ((struct.unpack('!B', pkt[tcp_start+12])[0]) >> 4) * 4 #length of tcp header in bytes
    	            protocol_str = 'TCP, src_port = %d, dst_port = %d' % (src_port, dst_port)
                    extra = [src_ip_net, dst_ip_net, src_port, dst_port, ip_id, pkt_dir, seqno] #used for deny tcp
                    http_start = tcp_start + tcp_length
                    http_pkt = pkt[http_start:]
                    payload_size = len(http_pkt)
                    
                    if pkt_dir == PKT_DIR_OUTGOING and dst_port == 80: #Outgoing HTTP packet => request
                        conn_id = (src_ip_str, dst_ip_str, src_port, dst_port)
                        match = self.match_tcp_conn(conn_id)
                        
                        if syn_set and (match == -1): #connection is being set up
                            print 'SYN packet received for '+str(conn_id)
                            assert not ack_set, 'SYNACK packet received instead of SYN, packet dropped'
                            status = 0
                            seqnos = (None, seqno+1) #seqnos holds next expected seqno
                            buff = ''
                            state = [conn_id, status, seqnos, buff]
                            self.connections.append(state)
                            print '>>connection created:'+str(state)
                            
                        elif (fin_set or rst_set) and (match != -1):
                            print 'FIN or RST packet received for '+str(conn_id)
                            print 'Connection Ended'
                            del self.connections[match]

                        elif match != -1: #connection initiated
                            conn = self.connections[match]
                            status = conn[1]
                            seqnos = conn[2]
                            #print'expecting seqno:'+str(seqnos)+' got int_seq:'+str(seqno)
                            expected = self.check_seqno(seqno, 'outgoing', seqnos)
                            assert expected == True, 'seqno check failed (outgoing)' #otherwise drop out of order packet

                            if status == 1: #this packet is ACK, last part of Handshake
                                assert ack_set, 'ack not set when it should be'
                                assert not syn_set, 'syn set when it sould not be, part 3 of handshake'
                                conn[1] += 1 #update status
                                print 'Handshake ACK received for:'+str(conn_id)
                                #seqnos stays the same unless data sent with ack
                                if payload_size > 0 :
                                    new_seq = (seqno+payload_size) % 0x100000000
                                    conn[2] = (seqnos[0], new_seq)
                                    headers = self.http_parse(http_pkt, 'request')
                                    if headers == False: #http header is incomplete
                                        buff = conn[3]
                                        buff += http_pkt
                                    elif headers[0] == None:
                                        headers[0] = conn[0][1] #Host = external ip
                                        
                                    if headers != False:
                                        print '>>HTTP request header successfully parsed:' + str(headers)
                                        transaction = [conn_id] #must create new transaction
                                        transaction += headers
                                        self.transactions.append(transaction)
                                        
                            elif status == 2: #deal with actual request
                                if ack_set:
                                    print '(outgoing) HTTP ACK for:'+str(conn_id)
                                else:
                                    assert payload_size >0, 'payload <= 0'
                                    print '(outgoing) HTTP packet received for:'+str(conn_id)
                                if payload_size > 0:
                                    new_seq = seqnos[1] + payload_size % 0x100000000 #next int_seq = old int_seq + payload % 2^32
                                    conn[2] = (seqnos[0], new_seq) #update seqnos
                                    t = self.match_trans(conn_id) #check to see if transaction already exists
                                    if t == -1:
                                        buff = conn[3]
                                        buff += http_pkt
                                        headers = self.http_parse(buff, 'request')
                                        if headers != False:
                                            print '>>Header for request successfully parsed:'+str(headers)
                                            if headers[0] == None:
                                                headers[0] = conn[0][1]
                                            transaction = [conn_id]
                                            transaction += headers
                                            self.transactions.append(transaction)
                                            buff = ''
                                            print '>>Created new transaction: '+str(transaction[1:])
                                    else:
                                        print '>>Probably continuation of request packet'
                        else: #no connection found
                            print 'No connection found, may be residual ACKs/FINs'
                            
                    elif pkt_dir == PKT_DIR_INCOMING and src_port == 80: #Incoming HTTP packet => response
                        conn_id = (dst_ip_str, src_ip_str, dst_port, src_port)
                        match = self.match_tcp_conn(conn_id)
                        if match == -1:
                            print 'No matching connection found, the connection may be shutting down'
                        else:
                            print 'Found matching connection at:' + str(self.connections[match])
                        
                        if (fin_set or rst_set) and (match != -1):
                            print 'FIN or RST packet received for '+str(conn_id)
                            print 'Connection Ended'
                            del self.connections[match]
                            match = -1
                        
                        if match != -1:
                            conn = self.connections[match]
                            status = conn[1]
                            seqnos = conn[2]
                            expected = self.check_seqno(seqno, 'incoming', seqnos)
                            assert expected == True, 'failed seqno check (incoming)'

                            if status == 0: #still in handshake, SYNACK
                                assert syn_set, 'syn bit not set (SYNACK)'
                                assert ack_set, 'ack bit not set (SYNACK)'
                                print 'SYNACK received for:'+str(conn_id)
                                conn[1] += 1 #update status
                                conn[2] = (seqno+1, seqnos[1]) #update seqnos, expect to get back rel seqno (1,1)
                                
                            elif status == 2: #process actual response
                                if ack_set:
                                    print 'ACK for an HTTP packet received:'+str(conn_id)
                                else:
                                    print 'HTTP packet received for:'+str(conn_id)
                                    assert payload_size > 0, 'payload <= 0 (incoming)'
                                if payload_size > 0:
                                    new_seq = (seqnos[0] + payload_size) % 0x100000000 #next ext_seq = old ext_seq + payload % 2^32
                                    conn[2] = (new_seq, seqnos[1]) #update seqnos
                                    t = self.match_trans(conn_id)
                                    if t != -1: #found matching transaction
                                        print '>>Found matching transaction'
                                        buff = conn[3]
                                        buff += http_pkt
                                        headers = self.http_parse(buff, 'response')
                                        if headers != False:
                                            print '>>Header successfully parsed:'+str(headers)
                                            transaction = self.transactions[t]
                                            transaction += headers
                                            assert len(transaction) == 7, 'transaction is not correct length' #transaction is complete
                                            if self.log_rule(transaction[1]):
                                                self.write_trans(transaction)
                                                print '>>Transaction written'
                                            del self.transactions[t]
                                    else:
                                        print '>>No transaction found, log probably already written and sending corresponding data'
                                    

    	            if pkt_dir == PKT_DIR_INCOMING:
    	                allow = self._match_rule('tcp', src_ip, src_port, False, extra)
    	            else:
    	                allow = self._match_rule('tcp', dst_ip, dst_port, False, extra)
    	        except IndexError:
                    print 'dropped unreadable TCP packet'
    	            allow = False
                except AssertionError as e:
                    print 'ERROR: '+str(e)+''
                    allow = False
		
            elif protocol == 17: #UDP packet
    	        udp_start = header_len*4 #get start of UDP header in bytes
    	        try:
    	            src_port = struct.unpack('!H', pkt[udp_start:udp_start+2])[0] #get and unpack src_port of UDP packet
    	            dst_port = struct.unpack('!H', pkt[udp_start+2:udp_start+4])[0]
    	            protocol_str = 'UDP, src_port = %d, dst_port = %d' % (src_port, dst_port)
    	        except IndexError:
    	            print 'dropped unreadable UDP packet'
    	            allow = False
    	            error = True
		
    	        if error == False and pkt_dir == PKT_DIR_OUTGOING and dst_port == 53: #DNS query
    	            dns_start = udp_start + 8 #udp header is always 8 bytes long
    	            try:
    	                num_questions = struct.unpack('!H', pkt[dns_start+4:dns_start+6])[0]
    	                q_start = dns_start + 12 #location of first question in DNS packet
    	                if num_questions != 1: #does not match spec of DNS query
    	                    allow = self._match_rule('udp', dst_ip, dst_port, False)
    	                else:
    	                    labels = []
    	                    label_len = struct.unpack('!B', pkt[q_start])[0] #get length of first label
    	                    q_start += 1 #beginning of first label
    	                    while label_len != 0:
    	                        label = ''
    	                        for i in range(0,label_len):#get each char of a label individually
    	                            ch = struct.unpack('!c', pkt[q_start+i])[0]
    	                            label += ch
    	                        q_start += label_len
    	                        labels.append(label)
    	                        label_len = struct.unpack('!B', pkt[q_start])[0] #next label length
    	                        q_start += 1
		                
    	                    q_type = struct.unpack('!H', pkt[q_start:q_start+2])[0]
    	                    q_class = struct.unpack('!H', pkt[q_start+2:q_start+4])[0]
    	                    if (q_type ==  1 or q_type == 28) and (q_class == 1):
    	                        protocol_str = 'UDP + DNS'
    	                        extra = [src_ip_net, dst_ip_net, src_port, dst_port, ip_id, pkt_dir, pkt[dns_start:]]
    	                        allow = self._match_rule('udp', dst_ip, dst_port, labels, extra)
    	                    else:
    	                        allow = self._match_rule('udp', dst_ip, dst_port, False)
                    except IndexError:
                        print('dropped malformed DNS packet') 
                        error = True 
                        allow = False  
		        
                elif error == False: #regular UDP packet
    	            if pkt_dir == PKT_DIR_INCOMING:
    	                allow = self._match_rule('udp', src_ip, src_port, False)
    	            else:
    	                allow = self._match_rule('udp', dst_ip, dst_port, False)
            else:
    	        allow = True #allow by default
        
            print '%s len = %4dB, type = %s, allow = %s %15s -> %15s' % (dir_str, len(pkt), protocol_str, allow, src_ip_str, dst_ip_str)
	        # ... and simply allow the packet.
            if (pkt_dir == PKT_DIR_INCOMING) and (allow == True):
                self.iface_int.send_ip_packet(pkt)
            elif (pkt_dir == PKT_DIR_OUTGOING) and (allow == True):
                self.iface_ext.send_ip_packet(pkt)
    
    def log_rule(self, host_name):
        #matches host_name (domain or ip address) with log http rules in rules.conf
        #either domain or ip address should be in string format
        if self._is_ip_addr(host_name):
            for addr in self.http_ip_rules:
                if host_name == addr:
                    return True
            return False
        else:
            labels = host_name.split('.')
            for domain_rule in self.http_domain_rules:
                print 'rule: %s' % (domain_rule)
                print 'match w/: %s' % (labels)
                if len(domain_rule) <= len(labels):
                    i = -1
                    match = None
                    for label in reversed(domain_rule):
                        try:
                            cur = labels[i]
                        except IndexError:
                            match = False
                            break
                            
                        if label == '*': #found wildcard
                            match = True
                            break
                        elif label != cur:
                            match = False
                            break
                        else:
                            i = i-1
                            
                    if match == None: #went through entire rule with no problems & no wildcard
                        try:
                            test = labels[i] #should be out of bounds if we went through entire match
                            match = False #if no error then no match
                        except IndexError:
                            match = True
                
                    if match == True:
                        return True
            return False
            
    def _is_ip_addr(self, string):
        #returns True if the stirng is a valid IP address, otherwise False
        #string is the ip address in string format
        try:
            socket.inet_aton(string)
            return True
        except:
            return False
    
    def write_trans(self, trans):
        #writes one line (one transaction) to the log file
        #trans is the transaction to be written
        log = open('http.log', 'a')
        for item in trans[1:]:
            log.write(item+' ')
        log.write('\n')
        log.flush()
        log.close()
    
    def match_trans(self, conn_id):
        #searches open transactions and matches based on connection id
        #returns index for that transaction or -1 for no match
        i = 0
        for t in self.transactions:
            if conn_id == t[0]:
                return i
            i += 1
        return -1
    
    def http_parse(self, http_pkt, type):
        #If request: returns tuple (Host, Method, Path, Version), Host may be None if Host field not present
        #If response: return tuple (Status Code, Content Length)
        #If packet is incomplete, ie found no '\r\n\r\n' returns False
        complete = http_pkt.find('\r\n\r\n') #represents end of HTTP header
        if complete == -1:
            return False
        elif type == 'request':
            fields = []
            h_index = http_pkt.find('Host:')
            if h_index != -1: #host field present
                host = http_pkt[h_index+6:]
                end = host.find('\r\n')
                host = host[:end]
            else:
                host = None
            fields.append(host)
            end = http_pkt.find(' ')
            method = http_pkt[:end]
            fields.append(method)
            path = http_pkt[end+1:]
            end = path.find(' ')
            path = path[:end]
            fields.append(path)
            v_index = http_pkt.find('HTTP/')
            version = http_pkt[v_index:v_index+8]
            fields.append(version)
            return fields
        else: #response
            fields =[]
            start = http_pkt.find(' ') #find first space in packet
            code = http_pkt[start+1:]
            end = code.find(' ')
            code = code[:end]
            fields.append(code)
            start = http_pkt.find('Content-Length')
            if start != -1:
                size = http_pkt[start+16:]
                end = size.find('\r\n') #find end of current line
                size = size[:end]
            else:
                size = '-1'
            fields.append(size)
            return fields
            
    
    def match_tcp_conn(self, conn_id):
        #searches open tcp connections based on connection id (int_ip, ext_ip, int_port, ext_port)
        #returns index of first matching connection or -1 for no match
        i=0
        for conn in self.connections:
            cur_id = conn[0]
            check = (conn_id[0] == cur_id[0])
            check = ((conn_id[1] == cur_id[1]) and check)
            check = ((conn_id[2] == cur_id[2]) and check)
            check = ((conn_id[3] == cur_id[3]) and check)
            if check:
                return i #found match
            else:
                i += 1
        return -1 #no match

    def check_seqno(self, check, dir, seqnos):
        #returns true if seqno = check based on direction
        if dir == 'incoming':
            match = seqnos[0]
            if match == None:
                return True
            else:
                return check == match
        else:
            match = seqnos[1]
            if match == None:
                return True
            else:
                return check == match
    
    def _match_rule(self, protocol, ext_ip, ext_port, dns, extra=None):
        #protocol is a lowercase string, ie 'udp', 'tcp', 'dns', 'icmp'
        #ext_ip is external ip in numerical form (already unpacked)
        #ext_port is external port in numerical form (already unpacked)
        #dns is False if not a dns query, or list of labels if it is a dns query
        #extra is an array or None holding data needed for the deny command
        
        allow = True #allow by default
        deny = False
        for rule in self.rules:
            if rule[0] == 'pass':
                temp_allow = True #if rule matches, allow will be set to true
                temp_deny = False
            elif rule[0] == 'deny':
                temp_allow = False
                if rule[1] == 'tcp':
                    temp_deny = 'tcp'
                elif rule[1] == 'dns':
                    temp_deny = 'dns'
                else:
                    continue
            else:
                temp_allow = False
                temp_deny = False
                
            if rule[1] == protocol: #protocol match
                if rule[2] == 'any': #ext_ip of rule is 'any'
                    if self._match_port(rule, ext_port):
                        allow = temp_allow
                        deny = temp_deny
                        continue
                        
                elif len(rule[2]) == 2: #country code
                    country = rule[2]
                    match = self._country_bsearch(ext_ip, 0, len(self.countries)-1)
                    if (match != None) and (match == country):
                        if self._match_port(rule, ext_port):
                            allow = temp_allow
                            deny = temp_deny
                            continue
                    
                else: #ip or ip prefix
                    ip = rule[2]
                    sep_index = ip.find('/')
                    if sep_index != -1: #there is an ip prefix
                        ip_addr = ip[:sep_index]
                        prefix = int(ip[sep_index+1:])
                        ip_addr_base = self.ipify(ip_addr) #get numerical ip addr base
                        mask = self._build_mask(32-prefix)
                        ip_addr_max = ip_addr_base | mask #numerical rep of ipp_addr_base with 1s added in prefix area
                        if (ext_ip >= ip_addr_base) and (ext_ip <= ip_addr_max):
                            if self._match_port(rule, ext_port):
                                allow = temp_allow
                                deny = temp_deny
                                continue
                        
                    else: #pure ip address
                        ip_addr_num = self.ipify(rule[2]) #get numerical representation of address
                        if ip_addr_num == ext_ip:
                            if self._match_port(rule, ext_port):
                                allow = temp_allow
                                deny = temp_deny
                                continue
                            
            elif (rule[1] == 'dns') and dns != False: #dns match
                dns_rule = rule[2].split('.')
                print 'rule: %s' % (dns_rule)
                print 'match w/: %s' % (dns)
                if len(dns_rule) <= len(dns):
                    i = -1 #reverse index to go through 'dns' list
                    match = None
                    for label in reversed(dns_rule):
                        try:
                            cur = dns[i]
                        except IndexError:
                            match = False
                            break
                            
                        if label == '*': #found wildcard
                            match = True
                            break
                        elif label != cur:
                            match = False
                            break
                        else:
                            i = i-1
                            
                    if match == None: #went through entire rule with no problems & no wildcard
                        try:
                            test = dns[i] #should be out of bounds if we went through entire match
                            match = False #if no error then no match
                        except IndexError:
                            match = True
                
                    if match == True:
                        allow = temp_allow
                        deny = temp_deny
                        continue
                        
        if deny != False:#last rule matched was deny
            pkt_dir = extra[5]
            src_ip = extra[0]
            dst_ip = extra[1]
            src_port = extra[2]
            dst_port = extra[3]
            ip_id = extra[4]
            
            if deny == 'tcp':
                seqno = extra[6]
                pkt = self.tcp_rst(src_ip, dst_ip, src_port, dst_port, seqno)
                pkt = self.ip_packet(src_ip, dst_ip, ip_id, 6, pkt)
            elif deny == 'dns':
                src_pkt = extra[6]
                pkt = self.dns_redirect(src_pkt, dns, '169.229.49.109')
                pkt = self.udp_packet(src_ip, dst_ip, src_port, dst_port, pkt)
                pkt = self.ip_packet(src_ip, dst_ip, ip_id, 17, pkt)
            
            if pkt_dir == PKT_DIR_OUTGOING:
                print('Denied outgoing %s packet' % deny)
                self.iface_int.send_ip_packet(pkt)
            else:
                print('Denied incoming %s packet' % deny)
                self.iface_ext.send_ip_packet(pkt)

        return allow 
        
    def _match_port(self, rule, ext_port):
        if rule[3] == 'any': #ext_port of rule is 'any'
            return True
        else: #port is num or range
            port = rule[3]
            sep_index = port.find('-')
            if sep_index == -1: #numerical port
                port = int(port) #convert string port to int
                if ext_port == port:
                    return True
                else:
                    return False
            else: # port is a range
                port_min = int(port[:sep_index])
                port_max = int(port[sep_index+1:])
                if (ext_port >= port_min) and (ext_port <= port_max): #match
                    return True
                else:
                    return False            
                   
    def _build_mask(self, length):
        #builds a mask of 'length' 1s.
        x = 0b0
        for i in range(0,length):
            x = x << 1
            x += 1
        return x
        
    def ipify(self, ip_str):
        #converts an ip string (ie '1.1.1.1') to numerical form
        ip = socket.inet_aton(ip_str)
        ip_num = struct.unpack('!L', ip)[0]          
        return ip_num

    def _country_bsearch(self, ip, imin, imax):
        #binary searches geoipdb.txt for range that fits ip and returns that country code. Returns None if no match found
        if imax < imin: #no match found
            return None
        else:
            imid = int((imin+imax)/2)
            cur = self.countries[imid]
            entry_start = self.ipify(cur[0])
            entry_end = self.ipify(cur[1])
            entry_country = cur[2]
            if (ip >= entry_start) and (ip <= entry_end): #match
                return entry_country
            elif entry_start > ip: #ip is in smaller half
                return self._country_bsearch(ip, imin, imid-1)
            elif entry_end < ip: #ip is in larger half
                return self._country_bsearch(ip, imid+1, imax)
                
    def ip_packet(self, src_ip, dst_ip, ip_id, prot, data):
        #builds an ip packet with no options and with payload data
        pkt = struct.pack('!B', 0b01000101) #version = 4, ihl =5
        pkt += struct.pack('!B', 0) #DSCP and ECN = 0
        length = 20 + len(data)
        pkt += struct.pack('!H', length) #total length of packet
        pkt += ip_id #ip_id should already be in network binary
        pkt += struct.pack('!H', 0) #flags and frag offset =0
        pkt += struct.pack('!B', 60) #TTL=60
        pkt += struct.pack('!B', prot) #protocol
        pkt += struct.pack('!H', 0) #checksum = 0 for now
        pkt += dst_ip #flip dst and src ips
        pkt += src_ip
        checksum = self._ip_checksum(pkt)
        pkt = pkt[:10] + struct.pack('!H', checksum) + pkt[12:]
        pkt += data
        return pkt
        
    def _ip_checksum(self, pkt):
        #calculates the checksum for ip packet 'pkt' and returns it
        sum = 0b0
        i = 0
        while i < len(pkt):
            try:
                sum += struct.unpack('!H', pkt[i:i+2])[0]
            except IndexError:
                temp = struct.unpack('!H', (pkt[i] + struct.pack('!B', 0)))[0] #pad with 0s if necessary
                sum += temp
            i += 2
            
        sum = (sum >> 16) + (sum & 0xFFFF)
        sum += (sum >> 16)
        
        return (sum ^ 0xFFFF)
        
                
    def tcp_rst(self, src_ip, dst_ip, src_port, dst_port, seqno):
        #builds TCP packet with RST bit set
        pkt = struct.pack('!H', dst_port) #dst_port of received packet is src of rst packet
        pkt += struct.pack('!H', src_port) #src_port of received packet is dst of rst packet
        pkt += struct.pack('!I', 0) #sequence number = 0
        pkt += struct.pack('!I', seqno+1) #ack num = 0
        pkt += struct.pack('!B', 0b01010000) #data offset=5 and NS field =0
        flags = 0b00010100 #rst,ack flaq set
        pkt += struct.pack('!B', flags)
        pkt += struct.pack('!H', 0) #windows size =0 
        pkt += struct.pack('!H', 0) #checksum = 0 for now
        pkt += struct.pack('!H', 0) #urgent pointer = 0
        checksum = self._checksum(pkt, src_ip, dst_ip, 0x0006)
        checksum = struct.pack('!H', checksum)
        pkt = pkt[:16] + checksum + pkt[18:]
        return pkt
        
    def _checksum(self, pkt, src_ip, dst_ip, prot):
        #builds checksum for tcp/udp pkts
        #everything should be in network binary
        i = 0
        sum = 0b0
        
        while i < len(pkt):
            try:
                sum += struct.unpack('!H', pkt[i:i+2])[0]
            except IndexError:
                print 'padding'
                temp = struct.unpack('!H', (pkt[i] + struct.pack('!B', 0)))[0]
                sum += temp
            i += 2
        
        tcp_len = len(pkt)
        pseudo = [struct.unpack('!H', src_ip[0:2])[0], struct.unpack('!H', src_ip[2:4])[0], struct.unpack('!H', dst_ip[0:2])[0], struct.unpack('!H', dst_ip[2:4])[0], tcp_len, prot]
        
        for item in pseudo:
            sum += item
        
        sum = (sum >> 16) + (sum & 0xFFFF)    
        sum += (sum >> 16)
        
        return (sum ^ 0xFFFF)
        
    def dns_redirect(self, src_pkt, labels, new_ip):
        #takes original dns request and returns response redirecting to new_ip (string)
        pkt = src_pkt
        pkt = pkt[:2] + struct.pack('!B', 0b10000000) + pkt[3:] #set response field and authoritative response field
        pkt = pkt[:6] + struct.pack('!H', 0x0001) + pkt[8:] #set num answers =1
        ans = ''
        for l in labels:
            ans += struct.pack('!B', len(l))
            i = 0
            while i < len(l):
                ans += struct.pack('!c', l[i])
                i += 1
        ans += struct.pack('!B', 0) #end of name
        ans += struct.pack('!H', 0x0001) #type is A
        ans += struct.pack('!H', 0x0001) #class is IN
        ans += struct.pack('!L', 0x00000001) #TTL is 1 second
        ans += struct.pack('!H', 0x0004) #RDATA is 4 bytes long
        ip = socket.inet_aton(new_ip)
        ans += ip
        
        pkt += ans
        return pkt
        
    def udp_packet(self, src_ip, dst_ip, src_port, dst_port, data):
        #creates udp packet with destination: src_port, source: dst_port
        pkt = ''
        pkt += struct.pack('!H', dst_port) #set src port
        pkt += struct.pack('!H', src_port) #set dst port
        pkt += struct.pack('!H', len(data)+8) #set length field
        pkt += struct.pack('!H', 0) #checksum set to 0
        pkt += data
        checksum = self._checksum(pkt, src_ip, dst_ip, 0x0011)
        pkt = pkt[:6] + struct.pack('!H', checksum) + pkt[8:]
        return pkt
