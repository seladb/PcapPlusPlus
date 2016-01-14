#pragma once

#include <iomanip>
#include <iostream>


/**
 * An auxiliary class for printing 2-column tables
 */
template<typename K, typename V>
class TablePrinter
{
public:
	/**
	 * C'tor - get column names with widths
	 */
	TablePrinter(std::string columnAName, int columnALen, std::string columnBName, int columnBLen) :
		m_ColumnALen(columnALen), m_ColumnAName(columnAName),
		m_ColumnBLen(columnBLen), m_ColumnBName(columnBName),
		m_FirstRow(true) {}

	/**
	 * D'tor
	 */
	virtual ~TablePrinter() {}

	/**
	 * Print a single row
	 */
	void printRow(K columnAData, V columnBData)
	{
		// if this is the first row printed - print the headline first
		if (m_FirstRow)
		{
			printHeadline();
			m_FirstRow = false;
		}

		// print the row
		std::cout << std::left << "| " << std::setw(m_ColumnALen) << columnAData << " | " << std::setw(m_ColumnBLen) << columnBData << " |" << std::endl;
	}

	/**
	 * Close the table - should be called after all rows were printed
	 */
	void closeTable()
	{
		// if no rows were printed - do nothing
		if (m_FirstRow)
			return;

		// print a closing line
	    for (int index = 0; index < m_ColumnALen+m_ColumnBLen+7; index++) \
    		std::cout << "-";
	    std::cout << std::endl;
	}

private:
	int m_ColumnALen;
	std::string m_ColumnAName;
	int m_ColumnBLen;
	std::string m_ColumnBName;
	bool m_FirstRow;

	/**
	 * Print the table headline
	 */
	void printHeadline()
	{
		std::cout << std::left << "| " << std::setw(m_ColumnALen) << m_ColumnAName << " | " << std::setw(m_ColumnBLen) << m_ColumnBName << " |" << std::endl;
	    for (int index = 0; index < m_ColumnALen+m_ColumnBLen+7; index++) \
    		std::cout << "-";
	    std::cout << std::endl;
	}
};
