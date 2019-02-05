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
#include <utmp.h>
#include <arpa/inet.h>

using namespace std;

class stat{
public:
	vector<string> names;
	vector<int> number;
};

stat sortData(string, string, string, stat, string, bool, vector<string>);
void displayData(int, vector<string>, vector<int>, string);
void fail2BanTotal(const char*);
void logSort(const char **, string *, bool, string *, bool, vector<string>, int);
void readUserLogin(const char **, int, string, vector<string>);
void sortLoginInfo(vector< vector<string> >, string, int, int, int);
bool displayLoginInfo(vector<string>, int, int, bool );

const char* countryConvert = "/usr/local/bin/conversion.txt"; // This will convert the two letter country codes to the full english names

int main(int argc, char *argv[]){
	// This is the path to the logs and files the info is stored in
	const char* authLog[2] = { "/var/log/auth.log",		// This contains the failed attemps for logging
	"/var/log/auth.log.1" };	// in to ssh and the usernames they tried
	const char* syslog[2] = { "/var/log/syslog",		// This is where Geoip stores its logs of the connections
	"/var/log/syslog.1" }; 	// that it blocked and the country of origin
	const char* fail2ban = "/var/log/fail2ban.log"; 	// This is where fail2ban keeps it's logs of what is banned and not
	const char* logins[2] = { "/var/log/wtmp",
	"/var/log/wtmp.1"};

	string help = "log-stats STRING [-f N FILTER [FILTER ...]] [-a] [-c COUNT]\n";
	help  += "\t\t[-m] [STRING ...]\n\n\n";
	help  += "Requried Arguments\n";
	help  += "\tSTRING\tMust be either ssh, geoip, f2b, or login\n";
	help  += "Optional Arguments\n";
	help  += "\t-h, --help\n\t\tDisplay this message\n";
	help  += "\t-a\tDisplay everything\n";
	help  += "\t-c COUNT\n";
	help  += "\t-f N FILTER\n\t\tN = number of strings to filter\n";
	help  += "\t\tFILTER = string to filter\n";
	help  += "\t-m\n\t\tUsed with login. Instead of sorting by time and date\n";
	help  += "\t\tthe login output will be sorted by users.\n";

	bool print = true;

	for(int i = 0; i < argc && print; i++){
		if(string(argv[i]) == "-h" || string(argv[i]) == "--help"){
			cout << help;
			print = false;
		}
	}

	if(print)
		cout << "SSH Attack Statistics" << '\n';

	string arg = "";
	string post = "";
	string next = "";
	vector<string> filter;
	int count = 0;
	string find[4];
	string message[2];
	string mode = "default";
	bool printed = false;

	for(int i = 1; i < argc && print; i++){
		int lineCount = -1;
		bool everything = false;
		int ran = 0;
		arg = string(argv[i]);
		if(i+1 < argc){
			post = string(argv[i+1]);
		}
		if(i+2 < argc){
			next = string(argv[i+2]);
		}
		transform(arg.begin(), arg.end(), arg.begin(), ::tolower);
		filter.clear();
		do{
			i += ran;
			if(post == "-a"){
				everything = true;
				i += 1 - ran;
			}
			if(post == "-c"){
				istringstream(next) >> lineCount;
				i += 2 - ran;
			}
			if(post == "-f"){
				istringstream(next) >> count;
				count += 2 - ran;
				for(int n = 3 - ran; n <= count; n++){
					filter.push_back(argv[i+n]);
				}
				i += count;
			}
			if(post == "-m"){
				mode = "multiUser";
				i += 1 - ran;
			}
			if(post == "-h" || post == "--help"){
			}
			if(i+1 < argc){
				post = string(argv[i+1]);
			}else{
				post = " ";
			}
			if(i+2 < argc){
				next = string(argv[i+2]);
			}
			ran = 1;
		}while(post.find("-") != -1);

		if(lineCount == -1 && !everything && (arg == "ssh" || arg == "geoip")){
			lineCount = 15;
		}

		if(arg == "ssh"){
			find[0] = "Failed password";	// This string is to do a rough general filter
			find[1] = "password for ";	// This is the string right before the chunk needed
			find[2] = " from";		// This is the string right after the chuck to be displayed
			find[3] = "invalid user ";	// This is for when some data has extra infomation that needs to be cleared before the chunk
			message[0] = "Username - Tries";
			//This is collecting the usernames that have been tried that are not enabled to be used to login to ssh
			logSort(authLog, find, false, message, false, filter, lineCount);
			printed = true;

		}else if(arg == "geoip"){
			find[0] = "DENY sshd";
			find[1] = "(";
			find[2] = ")";
			find[3] = "NULL";//Since there is no extra data, it can be set to something like NULL to avoid any conflict
			message[0] = "Top ";
			message[1] = " connections from foreign countries";
			//This is collecting the info about what foreign countries have tried to connect
			// to ssh and hvae been blocked
			if(everything){
				message[0] = "Connections from foreign countries";
				everything = false;
			}else{
				everything = true;
			}
			logSort(syslog, find, true, message, everything, filter, lineCount);
			printed = true;
		}else if(arg == "f2b"){
			fail2BanTotal(fail2ban);
			printed = true;
		}else if(arg == "login"){
			if(!everything){
				filter.push_back("LOGIN");
				filter.push_back("reboot");
				filter.push_back("shutdown");
				filter.push_back("runlevel");
				filter.push_back("0.0.0.0");
			}else{
				lineCount = 1000;
			}
			readUserLogin(logins, lineCount, mode, filter);
			printed = true;
		}
	}
	if(!printed && print)
		cout << "Error required arguments not supplied. -h, --help for help.\n";

	return 0;
} // End int main()

void logSort(const char* logFiles[], string sort[], bool conversion, string message[], bool dynamic, vector<string> filter, int count){
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
				if(count < tries.names.size() && count != -1){
					size = count;
				}else if(count != -1){
					size = tries.names.size();
				}
				stringstream stream;
				stream << message[0] << size << message[1];
				display = stream.str();

			}else{
				if(count < tries.names.size() && count != -1){
					size = count;
				}else{
					size = tries.names.size();
				}
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
		cout << " " << name[position] << " - " << number[position] << '\n';
		name.erase(name.begin() + position);
		number.erase(number.begin() + position);
	}
}

void readUserLogin(const char **fileLoc, int number, string mode, vector<string> filter){
	struct utmp input[1];
	vector< vector<string> > results;
	ifstream file(fileLoc[1], ios::in | ios::binary);
	char ip[INET6_ADDRSTRLEN];
	char time[29];	/*Mon Jan 01 00:00:00 2018 PST*/
	size_t found;

	int nameSize = 7;
	int ipSize = 8;

	for(int z = 0; z < 2; z++){
		if(file.is_open()){
			while(!file.eof()){
				vector<string> userinfo;
				struct utmp log;

				file.read((char*)input, sizeof(struct utmp));
				log = input[0];
				string loginLoc = log.ut_line;

				time_t tmp = log.ut_tv.tv_sec;
				strftime(time, 29, "%a %b %d %T %Y %Z", localtime(&tmp));
				stringstream ss;	/*Convert raw */
				ss << tmp;

				if(log.ut_addr_v6[1] || log.ut_addr_v6[2] || log.ut_addr_v6[3]){
					inet_ntop(AF_INET6, log.ut_addr_v6, ip, sizeof(ip));
				}else{
					inet_ntop(AF_INET, log.ut_addr_v6, ip, sizeof(ip));
				}

				userinfo.push_back(log.ut_user);
				userinfo.push_back(log.ut_line);
				userinfo.push_back(time);
				userinfo.push_back(ss.str());

				found = loginLoc.find("tty");
				if(found==string::npos){
					userinfo[1] = ip;
				}
				found = 0;
				for(int x = 0; x < filter.size(); x++){
					if(filter[x] == userinfo[0] || filter[x] == userinfo[1]){
						found = 1;
					}
				}
				if(userinfo[0].length() > 0 && tmp > 0 && found == 0){	/*This filters out the system logging in during runtime */
					int loc = results.size() - 1;
					if(loc < 0 || results[loc] != userinfo){ /* This keeps duplicate records from being created */
						if(userinfo[0].length() > nameSize){
							nameSize = userinfo[0].length();
						}
						if(userinfo[1].length() > ipSize){
							ipSize = userinfo[1].length();
						}
						results.push_back(userinfo);
					}
				}
			}
		}
		file.close();
		file.open(fileLoc[0], ios::in | ios::binary);
	}
	if(results.size() == 0){
		cout << "No login information found" << endl;
	}else{
		sortLoginInfo(results, mode, number, nameSize, ipSize);
	}
}

void sortLoginInfo(vector< vector<string> > results, string mode, int number, int nameSize, int ipSize){
	if(number == -1){
		number = 4;
	}
	bool headerDisp = false;
	vector<int> usedUsernames;
	int count = 0;

	for(int i = results.size() - 1; i >= 0 && count < number; i--){
		if(mode == "multiUser"){
			bool success = false;
			int used = -1;
			int endofLoop = usedUsernames.size() - 1;
			for(int n = 0; n < endofLoop; n+=number+1){
				if(results[i][0] == results[usedUsernames[n]][0]){
					success = true;
					if(usedUsernames[n+number] < number){
						used = n;
					}
				}
			}
			if(usedUsernames.size() < 1 || !success){
				usedUsernames.push_back(i);
				for(int x = 0; x < number - 1; x++){
					usedUsernames.push_back(-1);
				}
				usedUsernames.push_back(1);
			}else if(used > -1){
				for(int x = 0; x < number; x++){
					if(usedUsernames[used + x] == -1){
						usedUsernames[used + x] = i;
						x = number;
					}
				}
				usedUsernames[used + number] += 1;
			}
		}else{
			headerDisp = displayLoginInfo(results[i], nameSize, ipSize, headerDisp);
			count += 1;
		}
	}
	if(mode == "multiUser"){
		for( int i = 0; i < usedUsernames.size(); i+=number+1){
			for(int n = 0; n < number; n++){
				if(usedUsernames[n+i] != -1){
					headerDisp = displayLoginInfo(results[usedUsernames[n+i]], nameSize, ipSize, headerDisp);
				}
			}
		}
	}
}

bool displayLoginInfo(vector<string> info, int nSize, int iSize, bool header){
	string spaceOne;
	string spaceTwo;
	bool ran = false;
	do{
		string cellOne = info[0];
		string cellTwo = info[1];

		spaceOne = "   ";
		spaceTwo = "   ";

		if(ran){
			header = true;
		}
		if(!header){
			cellOne = "sername";
			cellTwo = "Location";
		}
		if(cellOne.length() < nSize){
			for(int n = 0; n < nSize - cellOne.length(); n++){
				spaceOne += " ";
			}
		}
		if(cellTwo.length() < iSize){
			for(int n = 0; n < iSize - cellTwo.length(); n++){
				spaceTwo += " ";
			}
		}
		if(!header){
			cout << endl << "Username" << spaceOne << "Location" << spaceTwo << "Date" << endl;
			cout << "-------------------------------------------" << endl;
		}
		ran = true;
	}while(!header);
	cout << " " << info[0] << spaceOne << info[1] << spaceTwo << info[2] << endl;

	return header;
}
