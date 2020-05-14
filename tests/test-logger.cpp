#include "../include/logger.h"

int init_test_logger_stdout()
{
    Logger::logger_init_stdout();
    Logger::debug("english test\n中文测试\n\n换行测试");
    Logger::info ("english test\n中文测试\n\n换行测试");
    return 0;
}

int int_test_logger_file()
{
    Logger::Logger logger("hello", "./hello.log");
    logger.debug("english test\n中文测试\n\n换行测试");
    logger.info ("english test\n中文测试\n\n换行测试");
    return 0;
}

int main()
{
    init_test_logger_stdout();
    int_test_logger_file();
    return 0;
}
