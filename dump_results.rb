#!/usr/bin/ruby

# dump_results.rb - Parses JSON variables produced by autorun.rb and
# queries BeEF backend
#
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

# RESTful API root endpoints
ATTACK_DOMAIN = "127.0.0.1"
RESTAPI_HOOKS = "http://" + ATTACK_DOMAIN + ":3000/api/hooks"
RESTAPI_LOGS = "http://" + ATTACK_DOMAIN + ":3000/api/logs"
RESTAPI_MODULES = "http://" + ATTACK_DOMAIN + ":3000/api/modules"
RESTAPI_ADMIN = "http://" + ATTACK_DOMAIN + ":3000/api/admin"

BEEF_USER = "beef"
BEEF_PASSWD = "beef"

def login
	response = RestClient.post "#{RESTAPI_ADMIN}/login",
                             { 'username' => "#{BEEF_USER}",
                               'password' => "#{BEEF_PASSWD}"}.to_json,
                             :content_type => :json,
                             :accept => :json
  	@token = JSON.parse(response.body)['token']
end

def get_results(session, mod, cmd_id)
  response = RestClient.get "#{RESTAPI_MODULES}/#{session}/#{mod}/#{cmd_id}", {:params => {:token => @token}}
  result = JSON.parse(response.body)
   print JSON.parse(result["data"])['data'].gsub!(/\<br\>/i , "\n")
end

login

f = File.open("auto.out","r+")

while (line = f.gets() )
  next if line.include? "*"
  data = JSON.parse(line)
  get_results(data["ses"], data["mod"], data["cmd"])

end


f.close()
