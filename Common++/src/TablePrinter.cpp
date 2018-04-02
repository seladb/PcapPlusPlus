#define LOG_MODULE CommonLogModuleTablePrinter

#include <iomanip>
#include <sstream>
#include <iostream>
#include <iterator>
#include "TablePrinter.h"
#include "Logger.h"

namespace pcpp
{

TablePrinter::TablePrinter(std::vector<std::string> columnNames, std::vector<int> columnWidths) :
	m_ColumnNames(columnNames), m_ColumnWidths(columnWidths),
	m_FirstRow(true), m_TableClosed(false)
{
	if (m_ColumnWidths.size() != m_ColumnNames.size())
	{
		LOG_ERROR("Cannot create table: number of column names provided is different than number of column widths provided");
		m_TableClosed = true;
	}
}

TablePrinter::~TablePrinter()
{
	closeTable();
}

bool TablePrinter::printRow(std::vector<std::string> values)
{
	// if table is already closed return false
	if (m_TableClosed)
	{
		LOG_ERROR("Table is closed");
		return false;
	}

	if (values.size() != m_ColumnWidths.size())
	{
		LOG_ERROR("Number of values in input doesn't equal to number of columns");
		return false;
	}

	// if this is the first row printed - print the headline first
	if (m_FirstRow)
	{
		printHeadline();
		m_FirstRow = false;
	}

	for (int i = 0; i < (int)m_ColumnWidths.size(); i++)
	{
		std::string val = values.at(i);
		if (val.length() > (size_t)m_ColumnWidths.at(i))
		{
			val.erase(m_ColumnWidths.at(i)-3, std::string::npos);
			val += "...";
		}

		std::cout << std::left << "| " << std::setw(m_ColumnWidths.at(i)) << val << " ";
	}

	std::cout << "|" <<  std::endl;

	return true;
}

bool TablePrinter::printRow(std::string values, char delimiter)
{
	std::string singleValue;
	std::istringstream valueStream(values);
	std::vector<std::string> valuesAsVec;
	while (std::getline(valueStream, singleValue, delimiter))
	{
		valuesAsVec.push_back(singleValue);
	}

	return printRow(valuesAsVec);
}

void TablePrinter::printSeparator()
{
	// if table is already closed return
	if (m_TableClosed)
	{
		LOG_ERROR("Table is closed");
		return;
	}

	int totalLen = 0;
	for (std::vector<int>::iterator iter = m_ColumnWidths.begin(); iter != m_ColumnWidths.end(); iter++)
	{
		totalLen += 2 + (*iter) + 1;
	}

	totalLen++;

	for (int index = 0; index < totalLen; index++)
		std::cout << "-";

	std::cout << std::endl;
}

void TablePrinter::closeTable()
{
	// if this method was already called - do nothing
	if (m_TableClosed)
		return;

	// if no rows were printed - do nothing
	if (m_FirstRow)
		return;

	printSeparator();

	m_TableClosed = true;
}

void TablePrinter::printHeadline()
{
	// if table is already closed return
	if (m_TableClosed)
	{
		LOG_ERROR("Table is closed");
		return;
	}

	printSeparator();

	for (int i = 0; i < (int)m_ColumnWidths.size(); i++)
	{
		std::cout << std::left << "| " << std::setw(m_ColumnWidths.at(i)) << m_ColumnNames.at(i) << " ";
	}

	std::cout << "|" <<  std::endl;

	printSeparator();
}

}
