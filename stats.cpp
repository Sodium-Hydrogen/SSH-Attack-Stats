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
#include <cctype>
#include <algorithm>

using namespace std;

class stat{
	public:
		vector<string> names;
		vector<int> number;
};

stat sortData(string, string, string, stat, string, bool, vector<string>);
void displayData(int, vector<string>, vector<int>, string);
void fail2BanTotal(const char*);
void logSort(const char **, string *, bool, string *, bool, vector<string>);

const char* countryConvert = "/usr/local/bin/conversion.txt"; // This will convert the two letter country codes to the full english names

int main(int argc, char *argv[]){
	// This is the path to the logs and files the info is stored in
	const char* authLog[2] = { "/var/log/auth.log",		// This contains the failed attemps for logging
				   "/var/log/auth.log.1" };	// in to ssh and the usernames they tried
	const char* syslog[2] = { "/var/log/syslog",		// This is where Geoip stores its logs of the connections
				  "/var/log/syslog.1" }; 	// that it blocked and the country of origin
	const char* fail2ban = "/var/log/fail2ban.log"; 	// This is where fail2ban keeps it's logs of what is banned and not

	cout << "SSH Attack Statistics" << '\n';

	string pre;
	string arg;
	string post;
	vector<string> filter;
	int count = 0;
	string find[4];
	string message[2];

	for(int i = 1; i < argc; i++){
	arg = string(argv[i]);
	transform(arg.begin(), arg.end(), arg.begin(), ::tolower);
	filter.clear();
	if(arg == "-f"){
		post = argv[i+1];
		istringstream(post) >> count;
		count += 3;
		for(int n = 3; n < count; n++){
			filter.push_back(argv[i+n]);
		}
		arg = argv[i+2];
		transform(arg.begin(), arg.end(), arg.begin(), ::tolower);
		i += count - 1;
	}
	if(arg == "ssh"){
		find[0] = "Failed password";	// This string is to do a rough general filter
		find[1] = "password for ";	// This is the string right before the chunk needed
		find[2] = " from";		// This is the string right after the chuck to be displayed
		find[3] = "invalid user ";	// This is for when some data has extra infomation that needs to be cleared before the chunk
		message[0] = "Username - Tries";
		//This is collecting the usernames that have been tried that are not enabled to be used to login to ssh
		logSort(authLog, find, false, message, false, filter);

	}else if(arg == "geoip"){
		find[0] = "DENY sshd";
		find[1] = "(";
		find[2] = ")";
		find[3] = "NULL";//Since there is no extra data, it can be set to something like NULL to avoid any conflict
		message[0] = "Top ";
		message[1] = " connections from foreign countries";
		//This is collecting the info about what foreign countries have tried to connect
		// to ssh and hvae been blocked
		logSort(syslog, find, true, message, true, filter);
	}else if(arg == "f2b"){
		fail2BanTotal(fail2ban);

	}
	}


	return 0;
} // End int main()

void logSort(const char* logFiles[], string sort[], bool conversion, string message[], bool dynamic, vector<string> filter){
	ifstream file;
	string line;
	stat tries;
	int size;
	for(int a = 0; a < 2; a ++){
		file.open(logFiles[a]);
		if(file.is_open()){
			while(getline(file, line)){
				if(line.find(sort[0]) != -1){
					tries = sortData(line, sort[1], sort[2], tries, sort[3], conversion, filter);
				}
			}
		}
		file.close();
		if(a == 1 && !tries.names.empty()){
			string display;
			if(dynamic){
				size = tries.names.size() / 2;
				if(size < 5){
					size = 5;
				}
				stringstream stream;
				stream << message[0] << size << message[1];
				display = stream.str();

			}else{
				size = tries.names.size();
				display = message[0];
			}
			displayData(size, tries.names, tries.number, display);
		}
	}


}


void fail2BanTotal(const char* logFile){
	ifstream file;
	string line;
	int pos;
	int size;

	// This will search the fail2ban log and find the totoal number of connections that
	// are currently jailed by fail2ban
	file.open(logFile);
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
}

//This takes the raw info and returns the info cleaned up into two vectors
stat sortData(string chunk, string begin, string end, stat data, string additional, bool convert, vector<string> filter){
	ifstream country;
	string line;
	int add = 1;
	int position = 0;
	bool success = false;
	bool found = false;

	if(chunk.find("repeated") != -1){
		position = chunk.find("repeated");
		string count = chunk.substr(position + 9, 1);
		istringstream(count) >> add;
	}
	if(chunk.find(additional) != -1){
		position = chunk.find(additional);
		chunk = chunk.substr(position + additional.length());
	}else{
		position = chunk.find(begin);
		chunk = chunk.substr(position + begin.length());
	}
	position = chunk.find (end);
	chunk = chunk.substr(0,position);
	success = false;
	if(convert){
		country.open(countryConvert);
		if(country.is_open()){
			while(getline(country, line) && !success){
				if(line.find(chunk) != -1){
					chunk = line.substr(3);
					success = true;
				}
			}
		}
	}
	for(int a = 0; a < filter.size(); a++){
		if(chunk == filter[a]){
			found = true;
		}
	}
	if(!found){
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
