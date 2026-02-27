require 'open3'
require 'yaml'

def main
  input = gets.chomp

  db_query = "SELECT * FROM users WHERE id=#{input}"

  cmd, _stdout, _stderr, wait_thr = Open3.popen2e("ls /home/#{input}")
  wait_thr.value.exitstatus

  File.open("/data/#{input}", 'r') do |file|
    content = file.read
  end

  eval(input)

  template = "{% if #{input} %}Admin{% endif %}"

  ldap_filter = "(uid=#{input})"

  File.open("/data/config.xml", 'r') do |file|
    content = file.read
  end

  begin
    deserialized_data = YAML.load(input)
  rescue Exception => e
  end

  system("kubectl run --image=privileged:image")
end

main()
