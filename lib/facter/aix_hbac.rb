#
#  FACT(S):     aix_hbac
#
#  PURPOSE:     This custom fact returns an array of elements based on the
#               global and node-local HBAC rules in Red Hat IdM that should
#               apply to this node.
#
#  RETURNS:     (hash)
#
#  AUTHOR:      Chris Petersen, Crystallized Software
#
#  DATE:        January 26, 2021
#
#  NOTES:       Myriad names and acronyms are trademarked or copyrighted by IBM
#               including but not limited to IBM, PowerHA, AIX, RSCT (Reliable,
#               Scalable Cluster Technology), and CAA (Cluster-Aware AIX).  All
#               rights to such names and acronyms belong with their owner.
#
#		NOTE:  THIS IS NON-WORKING CODE.  IT NEEDS YOUR LDAP PATHS AND
#		CREDENTIALS TO WORK, SO IT CANNOT BE POSTED ON THE FORGE AS-IS.
#
#-------------------------------------------------------------------------------
#
#  LAST MOD:    (never)
#
#  MODIFICATION HISTORY:
#
#	(none)
#
#-------------------------------------------------------------------------------
#
Facter.add(:aix_hbac) do
    #  This only applies to the AIX operating system
    confine :osfamily => 'AIX'

    #  Capture the installation status and version if it's there
    setcode do
        #  Define the hash we'll fill and return
        l_aixHBAC                 = {}
        l_aixHBAC['global']       = []
        l_aixHBAC['global_names'] = []
        l_aixHBAC['host']         = ''
        l_aixHBAC['local']        = []
        l_aixHBAC['local_names']  = []
        l_aixHBAC['path']         = ''
        l_aixHBAC['in_place']     = false

        #  Grab our host name, which ought to be our FQDN in AIX
        l_aixHBAC['host'] = Socket.gethostname

        #  2021/11/09 - cp - Make sure the host name is an FQDN, since this place is such a mess
        unless (l_aixHBAC['host'] =~ /unix/)
            l_aixHBAC['host'] = l_aixHBAC['host'] ++ '.example.com'
        end

        #
        #  NOTE:  THIS IS A KLUDGE THAT WILL STOP WORKING AT SOME POINT!
        #
        #  Figure out where to get a usable (grumble, gripe) ldapsearch
        l_aixHBAC['path'] = '/usr/bin/ldapsearch'
        if (File.exists? '/opt/IBM/ldap/V6.1/bin/ldapsearch')
            l_aixHBAC['path'] = '/opt/IBM/ldap/V6.1/bin/ldapsearch'
        end
        if (File.exists? '/opt/IBM/ldap/V6.2/bin/ldapsearch')
            l_aixHBAC['path'] = '/opt/IBM/ldap/V6.2/bin/ldapsearch'
        end
        if (File.exists? '/opt/IBM/ldap/V6.3/bin/ldapsearch')
            l_aixHBAC['path'] = '/opt/IBM/ldap/V6.3/bin/ldapsearch'
        end
        if (File.exists? '/opt/IBM/ldap/V6.4/bin/ldapsearch')
            l_aixHBAC['path'] = '/opt/IBM/ldap/V6.4/bin/ldapsearch'
        end

        #  Look for the global HBAC rules - putting the PW here is BAD!
        l_lines = Facter::Util::Resolution.exec(l_aixHBAC['path'] + ' -b "cn=hbac,dc=example,dc=com" -h YOURLDAPSERVERGOESHERE -D "uid=nss3,cn=sysaccounts,cn=etc,dc=example,dc=com" -w "YOURPASSWORDGOESHERE" hostCategory=all ipaUniqueID ipaEnabledFlag cn 2>/dev/null')

        #  Loop over the lines that were returned
        l_cn    = 'BS'
        l_ief   = 'FALSE'
        l_iuid  = 'BS'
        l_saved = false
        l_lines && l_lines.split("\n").each do |l_oneLine|
            #  Skip comments and blanks
            l_oneLine = l_oneLine.strip()

            #  Split regular lines, and stash the relevant fields
            if (l_oneLine == '') 
                if (l_ief != 'FALSE')
                    l_aixHBAC['global'].push('(memberOf=' + l_iuid + ')')
                    l_aixHBAC['global_names'].push(l_cn)
                    l_saved = true
                end
            else
                l_list = l_oneLine.split("=")
                if ((l_list[0] == 'ipaUniqueID') && (l_list[-1] == 'com'))
                    l_saved = false
                    l_iuid  = l_oneLine 
                end
                if (l_list[0] == 'cn')
                    l_cn   = l_list[1] 
                end
                if (l_list[0] == 'ipaEnabledFlag')
                    l_ief  = l_list[1] 
                end
            end
        end

        #  Make sure we process the end of the list
        if ((!l_saved) and (l_ief != 'FALSE'))
            l_aixHBAC['global'].push('(memberOf=' + l_iuid + ')')
            l_aixHBAC['global_names'].push(l_cn)
        end

        #  Look for the node-specific HBAC rules - putting the PW here is BAD!
        l_lines = Facter::Util::Resolution.exec(l_aixHBAC['path'] + ' -b "cn=hbac,dc=example,dc=com" -h YOURLDAPSERVERGOESHERE -D "uid=nss3,cn=sysaccounts,cn=etc,dc=example,dc=com" -w "YOURPASSWORDGOESHERE" ' +
                                                'memberHost=fqdn=' + l_aixHBAC['host'] + ',cn=computers,cn=accounts,dc=example,dc=com ipaUniqueID ipaEnabledFlag cn 2>/dev/null')

        #  Loop over the lines that were returned
        l_cn    = 'BS'
        l_ief   = 'FALSE'
        l_iuid  = 'BS'
        l_saved = false
        l_lines && l_lines.split("\n").each do |l_oneLine|
            #  Skip comments and blanks
            l_oneLine = l_oneLine.strip()

            #  Split regular lines, and stash the relevant fields
            if (l_oneLine == '') 
                if (l_ief != 'FALSE')
                    l_aixHBAC['local'].push('(memberOf=' + l_iuid + ')')
                    l_aixHBAC['local_names'].push(l_cn)
                    l_saved = true
                end
            else
                l_list = l_oneLine.split("=")
                if ((l_list[0] == 'ipaUniqueID') && (l_list[-1] == 'com'))
                    l_saved = false
                    l_iuid  = l_oneLine 
                end
                if (l_list[0] == 'cn')
                    l_cn   = l_list[1] 
                end
                if (l_list[0] == 'ipaEnabledFlag')
                    l_ief  = l_list[1] 
                end
            end
        end

        #  Make sure we process the end of the list
        if ((!l_saved) and (l_ief != 'FALSE'))
            l_aixHBAC['local'].push('(memberOf=' + l_iuid + ')')
            l_aixHBAC['local_names'].push(l_cn)
        end

        #  2021/11/08 - cp - See if we've already put HBAC rules in place
        l_lines = Facter::Util::Resolution.exec('/usr/bin/grep ^userbasedn /etc/security/ldap/ldap.cfg 2>/dev/null | /usr/bin/grep memberOf 2>/dev/null')

        #  Loop over the lines that were returned - just make this true if we got anything
        l_lines && l_lines.split("\n").each do |l_oneLine|
            l_aixHBAC['in_place'] = true
        end

        #  Implicitly return the contents of the hash
        l_aixHBAC
    end
end
