/*
This porogram was created by Michael Julander

It's purpose is to be run in the MOTD on a linux server
that has fail2ban, Geoip blocking, and Username and password entry
for SSH login

*/

#include <vector>
#include <iostream>
#include <fstream>
#include <string>
#include <sstream>

using namespace std;

class stat{
	public:
		vector<string> names;
		vector<int> number;
};

stat sortData(string, string, string, stat);
void displayData(int, vector<string>, vector<int>, string);

int main(){
	string line;
	string privateIP;
	int pos;
	int size;
	bool success = false;
	ifstream file;
	stat tries;

	// This is the path to the logs and files the info is stored in
	const char* ipFile = "/proc/net/fib_trie"; // This contains the ip of your computer given by the DHCP
	const char* authLog = "/var/log/auth.log"; // This contains the failed attemps for logging
	const char* authLogTwo = "/var/log/auth.log.1"; // in to ssh and the usernames they tried
	const char* syslog = "/var/log/syslog"; // This is where Geoip stores its logs of the connections
	const char* syslogTwo = "/var/log/syslog.1"; // that it blocked and the country of origin
	const char* fail2ban = "/var/log/fail2ban.log"; // This is where fail2ban keeps it's logs of what is banned and not

	cout << "SSH Attack Statistics" << '\n';

	//This is finding the private IP that the DHCP has given so your occational fail from home
	// doesn't show up in the statistics
	file.open(ipFile);
	if(file.is_open()){
		while(getline(file, line) && !success){
			if(line.find("UNICAST") != -1){
				getline(file, line);
				pos = line.find("+-- ");
				line = line.substr(pos + 4);
				pos = line.find_last_of(".");
				line = line.substr(0, pos);
				privateIP = line;
				success = true;
			}
		}
	}
	file.close();


	//This is collecting the usernames that have been tried that are not enabled to be used to
	// login to ssh
	file.open(authLog);
	for(int a = 0; a < 2; a ++){
		if(file.is_open() && success){
			while(getline(file, line)){
				if(line.find("Failed password") != -1 && line.find(privateIP) == -1){
					tries = sortData(line, "user ", " ", tries);
				}
			}
		}
		file.close();
		file.open(authLogTwo);
		if(a == 1 && success){
			size = tries.names.size();
			displayData(size, tries.names, tries.number, "Username - Tries");
		}
	}
	file.close();

	// Clear the old info out of the vectors
	tries.names.clear();
	tries.number.clear();


	//This is collecting the info about what foreign countries have tried to connect
	// to ssh and hvae been blocked
	file.open(syslog);
	for(int a = 0; a < 2; a++){
		if(file.is_open()){
			while(getline(file, line)){
				if(line.find("DENY sshd") != -1){
					tries = sortData(line, "(", ")", tries);
				}
			}
		}
		file.close();
		file.open(syslogTwo);
		if(a == 1){
			displayData(5, tries.names, tries.number, "Top 5 connections from foreign countries");
		}
	}
	file.close();


	// This will search the fail2ban log and find the totoal number of connections that
	// are currently jailed by fail2ban
	file.open(fail2ban);
	if(file.is_open()){
		vector<string> ban;
		vector<string> unban;
		while(getline(file, line)){
			if(line.find("NOTICE") != -1){
				if(line.find("already") != -1){
					// Do Nothing because we don't care if it's already banned
				}else if(line.find("Ban ") != -1){
					pos = line.find("Ban ");
					ban.push_back(line.substr(pos+4));
				}else{
					pos = line.find("Unban ");
					unban.push_back(line.substr(pos+6));
				}
			}
		}
		size = ban.size();
		for(int i = 0; i < ban.size(); i++){
			pos = -1;
			for(int n = 0; n < unban.size(); n++){
				if(ban[i] == unban[n]){
					size -= 1;
					pos = n;
					n = unban.size();
				}
			}
			if(pos != -1){
				unban.erase(unban.begin() + pos);
			}
		}
		cout << '\n' << "Total IPs currently banned - " << size << '\n';
	}
	file.close();

	return 0;
} // End int main()

//This takes the raw info and returns the info cleaned up into two vectors
stat sortData(string chunk, string begin, string end, stat data){
	int add = 1;
	int position = 0;
	bool success = false;

	if(chunk.find("repeated") != -1){
		position = chunk.find("repeated");
		string count = chunk.substr(position + 9, 1);
		istringstream(count) >> add;
	}
	position = chunk.find(begin);
	chunk = chunk.substr(position + begin.length());
	position = chunk.find (end);
	chunk = chunk.substr(0,position);
	success = false;
	for(int i = 0; i < data.names.size(); i++){
		if(data.names[i] == chunk){
			success = true;
			data.number[i] += add;
		}
	}
	if(!success){
		data.names.push_back(chunk);
		data.number.push_back(add);
	}
	return data;
}//End stat sortData()

//This displays and sorts the data
void displayData(int rows, vector<string> name, vector<int> number, string title){
	cout << '\n' << title << '\n' << "-------------------------------------------" << '\n';
	int position = 0;
	for(int i = 0; i < rows; i++){
		position = 0;
		for(int n = 0; n < name.size(); n++){
			if(number[n] > number[position]){
				position = n;
			}
		}
		cout << name[position] << " - " << number[position] << '\n';
		name.erase(name.begin() + position);
		number.erase(number.begin() + position);
	}
}
