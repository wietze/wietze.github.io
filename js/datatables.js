$(document).ready(function () {
    if ($(".data-table").length) {
        table = $('.data-table').DataTable({
            autoWidth: false,
            scrollCollapse: true,
            paging: false,
            dom: '<"top"if><"table"rt><"clear">',
            language: {
                info: "Showing <strong>_TOTAL_</strong> entries",
                infoEmpty: "Showing 0 entries",
                infoFiltered: "(filtered from <strong>_MAX_</strong> total entries)"
            }
        });
        if($(".hijack-table").length){
            MergeGridCells();
            table.on('draw', function () { MergeGridCells() })
            table.columns.adjust().draw();
        }
    }
});

function MergeGridCells() {
    // Reset first
    $(".data-table").find("td").attr('hidden', false).attr('rowspan', 1)

    var dimension_cells = new Array();
    var dimension_col = null;
    var offset = 2
    var columnCount = 2;
    for (dimension_col = offset; dimension_col < offset + columnCount; dimension_col++) {
        // first_instance holds the first instance of identical td
        var first_instance = null;
        var rowspan = 1;
        // iterate through rows
        $(".data-table").find('tr').each(function () {
            // find the td of the correct column (determined by the dimension_col set above)
            var dimension_td = $(this).find('td:nth-child(' + dimension_col + ')');

            if (first_instance === null) {
                // must be the first row
                first_instance = dimension_td;
            } else if (dimension_td.text().toLowerCase() === first_instance.text().toLowerCase()) {
                // the current td is identical to the previous
                // remove the current td
                // dimension_td.remove();
                dimension_td.attr('hidden', true);
                ++rowspan;
                // increment the rowspan attribute of the first instance
                first_instance.attr('rowspan', rowspan);
            } else {
                // this cell is different from the last
                first_instance = dimension_td;
                rowspan = 1;
            }
        });
    }
}
