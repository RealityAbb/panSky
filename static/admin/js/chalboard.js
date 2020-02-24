function loadchal(id) {
    // $('#chal *').show()
    // $('#chal > h1').hide()
    obj = $.grep(challenges['game'], function (e) {
        return e.id == id;
    })[0]
    $('#update-challenge .chal-name').val(obj.name)
    $('#update-challenge .chal-desc').html(obj.description)
    $('#update-challenge .chal-value').val(obj.value)
    $('#update-challenge .chal-category').val(obj.category)
    $('#update-challenge .chal-flag').val(obj.flag)
    $('#update-challenge .chal-id').val(obj.id)
	if( obj.visible == 1) { 
		$('#update-challenge .chal-visible').attr("checked", true)
	} else { 
		$('#update-challenge .chal-visible').attr("checked", false)
	}
    $('#update-challenge .chal-delete').attr({
        'href': '/admin/chal/close/' + (id + 1)
    })
    $('#update-challenge').foundation('reveal', 'open');

}

function submitkey(chal, key) {
    $.post("/admin/chal/" + chal, {
        key: key,
        'nonce': $('input[name="nonce"]').val(),
    }, function (data) {
        alert(data)
    })
}

function loadfiles(chal){
    $('#update-files > form').attr('action', '/admin/files/'+chal)
    $.get('/admin/files/' + chal, function(data){
        $('#files-chal').val(chal)
        files = $.parseJSON(JSON.stringify(data));
        files = files['files']
        $('#current-files').empty()
        for(x=0; x<files.length; x++){
            filename = files[x].file.split('/')
            filename = filename[filename.length - 1]
            $('#current-files').append('<div data-alert class="alert-box info radius">'+filename+'<a href="#" onclick="deletefile('+chal+','+files[x].id+', $(this))" value="'+files[x].id+'" style="float:right;">删除</a></div>')
        }
    });
}

function deletefile(chal, file, elem){
    $.post('/admin/files/' + chal,{
        'nonce': $('input[name="nonce"]').val(),
        'method': 'delete', 
        'file': file
    }, function (data){
        if (data == "1") {
            elem.parent().remove()
        }
    });
}

function loadchals(){
    $.get("/admin/chals", {
        'nonce': $('input[name="nonce"]').val()
    }, function (data) {
        categories = [];
        challenges = $.parseJSON(JSON.stringify(data));


        for (var i = challenges['game'].length - 1; i >= 0; i--) {
            if ($.inArray(challenges['game'][i].category, categories) == -1) {
                categories.push(challenges['game'][i].category)
                $('#challenges').append($('<tr id="' + challenges['game'][i].category.replace(/ /g,"-") + '"><td class="large-2"><h3>' + challenges['game'][i].category + '</h3></td></tr>'))
            }
        };

        for (var i = categories.length - 1; i >= 0; i--) {
            $('#new-challenge select').append('<option value="' + categories[i] + '">' + categories[i] + '</option>');
            $('#update-challenge select').append('<option value="' + categories[i] + '">' + categories[i] + '</option>');
        };

        for (var i = challenges['game'].length - 1; i>=0 ; i--) {
			var invisible="";
			if (challenges['game'][i].visible == 0){ invisible="class='secondary'"; }

            $('#' + challenges['game'][i].category.replace(/ /g,"-")).append($('<button ' +invisible+ ' value="' + challenges['game'][i].id + '">' + challenges['game'][i].value + '</button>'));
        };

        $('#challenges button').click(function (e) {
            loadchal(this.value);
            loadfiles(this.value);
        });

        $('tr').append('<button class="create-challenge"><strong>＋</strong></button>');

        $('.create-challenge').click(function (e) {
            $('#new-chal-category').val($($(this).siblings()[0]).text().trim())
            $('#new-chal-title').text($($(this).siblings()[0]).text().trim())
            $('#new-challenge').foundation('reveal', 'open');
        });

    });
}

$('#submit-keys').click(function (e) {
    if (confirm('Updating keys. Are you sure?')){
        updatekeys()
    }
});

$('.create-category').click(function (e) {
	$('#new-category').foundation('reveal', 'open');
});

$(function(){
	loadchals()
})
