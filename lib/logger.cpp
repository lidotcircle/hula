#include "../include/logger.h"

#include <errno.h>
#include <stdlib.h>
#include <assert.h>

#include <vector>
#include <tuple>

#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))

const char * __ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
std::string random_string(size_t s) //{
{
    std::string ret = "";
    std::srand(std::time(nullptr));
    for(size_t i = 1; i<=s; i++)
    {
        char x = (std::rand() % ('z' - 'a' + 'Z' - 'A' + 2)) + 'A';
        if(x > 'Z'){x += ('a' - 'Z' - 1);}
        ret.push_back(x);
    }
    return ret;
} //}

namespace Logger {

void Logger::helloLogger() //{
{
    this->pid = GETPID();
    *this->outputStream << "------------ log of process [" << this->pid << "] -----------" << std::endl;
} //}

void Logger::initializeOutputFile() //{
{
    char default_log_file[_PATH_MAX * 2];
#if defined(_WIN32) || defined(_WIN64)
    GetEnvironmentVariable((LPCSTR)"USERPROFILE", (LPSTR)default_log_file, _PATH_MAX);
#else
    const char* home_path = ::getenv("HOME"); // TODO
    strcpy(default_log_file, home_path);
#endif // defined(_WIN32) || defined(_WIN64)
    strcat(default_log_file, "/");
    strcat(default_log_file, this->title.c_str());
    strcat(default_log_file, ".log");

    this->fileName = std::string(default_log_file);
} //}
void Logger::initializeOutputStream() //{
{
    this->outputStream = new std::fstream(this->fileName, std::ios_base::out | std::ios_base::app);
    if(errno != 0) {
        std::cout << "FATAL Open file '" << this->fileName.c_str() << "' fail!" << std::endl;
        abort();
    } else {
        this->helloLogger();
        return;
    }
} //}
void Logger::initializeTitle(const char* t) //{
{
    char* buf = (char*)malloc(strlen(t) + 256);
    this->pid = (uint32_t)GETPID();
    sprintf(buf, "%d-%s", this->pid, t);
    this->title = std::string(buf);
    free(buf);
} //}

Logger::Logger()//{
{
    this->title = random_string();
    this->initializeOutputFile();
    this->initializeTitle(this->title.c_str());
    this->initializeOutputStream();
} //}
Logger::Logger(const std::string& title, const char* filename): //{
    fileName(filename)
{
    this->initializeTitle(title.c_str());
    this->initializeOutputStream();
} //}
Logger::Logger(const std::string& title, const std::string& filename): //{
    fileName(filename)
{
    this->initializeTitle(title.c_str());
    this->initializeOutputStream();
} //}
Logger::Logger(const std::string& title, std::ostream& outstream): //{
    fileName("")
{
    this->initializeTitle(title.c_str());
    this->outputStream = &outstream;
    this->helloLogger();
} //}
Logger::Logger(const std::string& title) //{
{
    this->title = title;
    this->initializeOutputFile();
    this->initializeTitle(this->title.c_str());
    this->initializeOutputStream();
} //}

Logger::~Logger() //{
{
    *this->outputStream << std::endl;
    std::fstream* x = dynamic_cast<std::fstream*>(this->outputStream);
    if(x != nullptr) {
        x->close();
        delete this->outputStream;
    }
    this->outputStream = nullptr;
} //}

void Logger::begin_log(const std::string& level) //{
{
	time_t t = ::time(NULL);
	struct tm _time_;
    LOCAL_TIME(_time_, t);

	*this->outputStream << "[" << this->title.c_str() << " ";
	*this->outputStream
		<< std::setw(2) << std::right << _time_.tm_mon + 1 << "-" 
		<< std::setfill('0') << std::setw(2) << std::right << _time_.tm_mday  << " "
		<< std::setfill('0') << std::setw(2) << std::right << _time_.tm_hour << ":" 
		<< std::setfill('0') << std::setw(2) << std::right << _time_.tm_min << ":" 
        << std::setfill('0') << std::setw(2) << std::right << _time_.tm_sec << " "
        << std::setfill(' ') << std::setw(5) << level.c_str() << "]  ";
} //}
void Logger::new_line() //{
{
    size_t paddingSpace = 25 + ::strlen((char*)this->title.c_str());
    *this->outputStream << std::endl << std::string(paddingSpace, ' ').c_str();
} //}

void Logger::__logger(const std::string& level, const char* msg) //{
{
    char buf[4096];
    this->begin_log(level);
    int len = strlen(msg);
    if(len == 0) {
        *this->outputStream << std::endl;
        return;
    }
    std::vector<std::tuple<int, int>> msg_split;
    int p = 0;
    int l = strlen(msg);
    for(int i = 0; i<l; i++) {
        if(msg[i] == '\n') {
            msg_split.push_back(std::make_tuple(p, i));
            p = i + 1;
        }
    }
    msg_split.push_back(std::make_tuple(p, l));
    for(auto x: msg_split) {
        int a, b;
        std::tie(a, b) = x;
        assert( a <= b );
        if(a <= b) {
            strncpy(buf, &msg[a], b - a);
            buf[b - a] = '\0';
            *this->outputStream << (char*)buf;
        }
        if(b != l) this->new_line();
        else *this->outputStream << std::endl;
    }
} //}

void Logger::debug(const char* msg) //{
{
    if(this->Level > LOGGER_DEBUG) return;
    this->__logger("debug", msg);
} //}
void Logger::info (const char* msg) //{
{
    if(this->Level > LOGGER_DEBUG) return;
    this->__logger("info", msg);
} //}
void Logger::warn(const char* msg) //{
{
    if(this->Level > LOGGER_DEBUG) return;
    this->__logger("warn", msg);
} //}
void Logger::error(const char* msg) //{
{
    if(this->Level > LOGGER_DEBUG) return;
    this->__logger("error", msg);
} //}

Logger* logger = nullptr;
bool register_logger_cleaner = false;

void free_logger() //{
{
    if(logger != nullptr) {
        delete logger;
        logger = nullptr;
    }
} //}
void logger_init_stdout() //{
{
    if(logger != nullptr) return;
    logger = new Logger(random_string(), std::cout);
    if(register_logger_cleaner) return;
    register_logger_cleaner = true;
    atexit(free_logger); // ease valgrind
} //}

}
