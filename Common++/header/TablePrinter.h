#include <vector>

/// @file

/**
 * \namespace pcpp
 * \brief The main namespace for the PcapPlusPlus lib
 */
namespace pcpp
{
	/**
	 * A class for printing tables in command-line
	 */
	class TablePrinter
	{
	public:
		/**
		 * C'tor - get column names and column widths
		 * @param[in] columnNames A vector of strings containing column names
		 * @param[in] columnWidths A vector of integers containing column widths
		 */
		TablePrinter(std::vector<std::string> columnNames, std::vector<int> columnWidths);

		/**
		 * A d'tor for this class. Closes the table if not closed
		 */
		virtual ~TablePrinter();

		/**
		 * Print a single row by providing a single string containing all values delimited by a specified character.
		 * For example: if specified delimiter is '|' and there are 3 columns an example input can be:
		 * "value for column1|value for column2|value for column3"
		 * @param[in] values A string delimited by a specified delimiter that contains values for all columns
		 * @param[in] delimiter A delimiter that separates between values of different columns in the values string
		 * @return True if row was printed successfully or false otherwise (in any case of error an appropriate message
		 * will be printed to log)
		 */
		bool printRow(std::string values, char delimiter);

		/**
		 * Print a single row
		 * @param[in] values A vector of strings containing values for all columns
		 * @return True if row was printed successfully or false otherwise (in any case of error an appropriate message
		 * will be printed to log)
		 */
		bool printRow(std::vector<std::string> values);

		/**
		 * Print a separator line
		 */
		void printSeparator();

		/**
		 * Close the table - should be called after all rows were printed. Calling this method is not a must as it's called
		 * in the class d'tor
		 */
		void closeTable();

	private:
		std::vector<std::string> m_ColumnNames;
		std::vector<int> m_ColumnWidths;
		bool m_FirstRow;
		bool m_TableClosed;

		/**
		 * Print the table headline
		 */
		void printHeadline();
	};

}
