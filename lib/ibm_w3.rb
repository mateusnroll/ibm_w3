require 'ibm_w3/version'
require 'ldap'

module IBMW3

	class Authenticate
		@@host = 'bluepages.ibm.com'
		@@base = 'ou=bluepages,o=ibm.com'
		@@port = 636

		def self.do(email, password)
	    user = find_user_from_email(email)

	    if user.nil?
	    	puts "Cant find DN"
	    	return
	    end

	    if self.authenticated?(user[:dn], password)
	    	puts "Authenticated"
	    else
	    	puts "Wrong password"
	    end
		end

		private

		def self.map_entry_to_user(entry)
			entry = entry.to_hash()
			{
				dn: entry['dn'][0],
				email: entry['mail'][0],
				country: entry['c'][0],
				shortname: entry['notesshortname'][0],
				name: entry['cn'][0]
			}
		end

		def self.find_user_from_email(email)
			user, found = nil, false
			filter = "(&(objectclass=ibmPerson)(mail=#{email}))"
	    searchAttributes = ['dn', 'mail', 'cn', 'c', 'notesshortname']

	    LDAP::SSLConn.new(@@host, @@port).bind do |conn|
	    	conn.search(@@base, LDAP::LDAP_SCOPE_SUBTREE, filter, searchAttributes) do |entry|
					found = true
					user = self.map_entry_to_user(entry)
				end
	    end

			return nil unless found
			return user
		rescue LDAP::ResultError
			puts "DN NOT FOUND"
			return nil
		end

		def self.authenticated?(dn, password)
			connection = nil

			LDAP::SSLConn.new(@@host, @@port).bind do |conn|
	      connection = conn
	    end

	    connection.bind(dn, password)

	    return true if connection
	    return false
	  rescue LDAP::ResultError
	  	return false
		end
	end

end
