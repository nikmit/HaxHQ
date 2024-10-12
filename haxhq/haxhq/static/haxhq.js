const base_url = window.location.origin

if(typeof(String.prototype.trim) === "undefined") {
    String.prototype.trim = function() {
        return String(this).replace(/^\s+|\s+$/g, '');
    };
}

function install_update(pkg) {
    $('#update_' + pkg).prop('disabled', true);
    $('#update_' + pkg).text('Updating...').removeClass('green_btn').addClass('blue_btn').css('cursor', 'wait');
    var url = '/update/' + pkg;
    $.getJSON( url, function( data ) {
        if (data.success) {
            $('#update_' + pkg).text('Updated').removeClass('blue_btn').addClass('green_btn').css('cursor', 'not-allowed');
        } else {
            $('#update_' + pkg).text('Failed').removeClass('blue_btn').addClass('red_btn').css('cursor', 'not-allowed');
            $('#' + pkg + '_error').text(data.error).css('display', 'block');
        }
    });
}

function load_issue(data) {
    let current_user = data.current_user;
    let user_list = data.user_list;
    let issue = data.issue_versions[current_user];
    if (typeof(issue) == 'undefined') {
        issue = data.issue_versions[user_list[0]];
        current_user = user_list[0];
        //console.log('switching current_user to ' + current_user);
    } else {
        // only show the delete button if the current user has a version of this issue defined
        $('#delLib').removeClass('hidden');
    }

    $('#formtitle').text(issue.title);
    for (v in issue) {
        $('#' + v).val(issue[v]);
    }

    $('#altlib').empty();
    for (u in data.issue_versions) {
        if (u == current_user) {
            $('#altlib').append("<span class='lib_loaded'>" + u + "</span>");
        } else {
            let obj = $('<a>', {class: 'libentry', src: u, text: u})
            obj.on('click', function() {
                data.current_user = $(this).text();
                load_issue(data);
            });
            $('#altlib').append(obj);
        }
    }
    toggle_select_color('#severity');
    toggle_select_color('#exposure');
}

function empty_issue() {
    $('textarea','#libview').val('');
    $('#altlib').empty();
    $('#formtitle').empty();
    //$('#name').focus();
}

function update_severity(cvss_score) {
    var cvssmap = { '10': '4', '9': '4', '8': '3', '7': '3', '6': '2', '5': '2', '4': '2', '3': '1', '2': '1', '1': '1', '0': '1'};
    var cvssint;
    if (cvss_score == 0) {
        $('#severity').val('0').change();
    } else {
        cvssint = cvss_score.split('.')[0]
        $('#severity').val(cvssmap[cvssint]).change();
    }
}

function toggle_select_color(el) {
    var bodyStyles = window.getComputedStyle(document.body);
    let crit = bodyStyles.getPropertyValue('--crit-bg-color');
    let high = bodyStyles.getPropertyValue('--high-bg-color');
    let medium = bodyStyles.getPropertyValue('--medium-bg-color');
    let low = bodyStyles.getPropertyValue('--low-bg-color');
    let info = bodyStyles.getPropertyValue('--info-bg-color');
    let white = bodyStyles.getPropertyValue('--white-text');
    let internal = bodyStyles.getPropertyValue('--internal-bg-color');
    let external = bodyStyles.getPropertyValue('--external-bg-color');
    let grey = bodyStyles.getPropertyValue('--card-bg-color');
    switch ($(el).val()) {
        case 'adreview'     :
        case 'internal'     : $(el).css('background-color', internal);
                              $('.issue_hosts').css('background-color', internal);
                              $('#issue_hosts').css('background-color', internal); break;
        case 'external'     : $(el).css('background-color', external);
                              $('.issue_hosts').css('background-color', external);
                              $('#issue_hosts').css('background-color', external); break;
        case 'selectexp'    : $(el).css('background-color', grey);
                              $('.issue_hosts').css('background-color', grey);
                              $('#issue_hosts').css('background-color', grey); break;
        case '4'            : $(el).css({'background-color': crit, 'color': white}); break;
        case '3'            : $(el).css({'background-color': high, 'color': 'black'}); break;
        case '2'            : $(el).css({'background-color': medium, 'color': 'black'}); break;
        case '1'            : $(el).css({'background-color': low, 'color': 'black'}); break;
        case '0'            : $(el).css({'background-color': info, 'color': 'black'}); break;
    }
}

function confirm_lib_update() {
    let confirm_text = '';
    $('.new_scanner_text.current_text').each(function() {
        let field = $(this).attr('class').split(/\s+/)[1];
        if (confirm_text != '') {
            confirm_text += '\n\n';
        }
        confirm_text += 'This will overwrite your ' + field + ' text in library with the new scanner text.';
    });
    $('.old_scanner_text.current_text').each(function() {
        let field = $(this).attr('class').split(/\s+/)[1];
        if (confirm_text != '') {
            confirm_text += '\n\n';
        }
        confirm_text += 'This will overwrite your ' + field + ' text in library with the old scanner text.';
    });
    if (confirm_text != '') {
        return confirm(confirm_text);
    } else {
        return true;
    }
}

$.fn.exists = function () {
    return this.length !== 0;
}

$(window).resize(function() {
    hidemobnav();
});

function hidemobnav() {
        if ( $('#menu-overlay').is(':visible') ) {
          //only hide user menu if popup is on, else it hides the desktop user menu on resize 
          $('#user-menu').css('visibility', 'hidden');
        } else {
          $('#user-menu').css('visibility', 'visible');
        }
        if ( $(window).width() < 1080 ) {
          $('#burgerimg').show();
        } else {
          $('#burgerimg').hide();
        }

        $('#menu-overlay').hide();
        $('#crossimg').hide();
        $('#header-menu').removeAttr('style');
        $('.fromdropdown').removeClass('fromdropdown').addClass('dropdown').removeAttr('style');
}

var idleTime = 0;
$(document).ready(function(){
    var bodyStyles = window.getComputedStyle(document.body);

    $('#sendmail').click(function(){
        var href = $(this).attr('href') + '&body=' + $('#message').val().replace(/\n/g, '%0A');
        $(this).attr('href', href);
        return true;
    });
    //console.log($(window).width());
    if ($('.user').length && $('#timeoutwarn').length) {
        let timeout = 120;      // 2 min
        let timeoutwarn = 60;   // 1 min
        // Increment the idle time counter every minute.
        let idleInterval = setInterval(timerIncrement, 1000); // 1 sec 
        let idleTime = 0;
        // Zero the idle timer on mouse movement.
        $('#page').mousemove(function () { idleTime = 0; $('#timeoutwarn').css('visibility', 'hidden'); });
        $('#page').keypress(function () { idleTime = 0; $('#timeoutwarn').css('visibility', 'hidden'); });

        function timerIncrement() {
            idleTime = idleTime + 1;
            if ((timeout - idleTime) < timeoutwarn) {
                $('#timeoutwarn').css('visibility', 'visible');
            }
            console.log(timeout - idleTime);
            $('#timeleft').text(timeout - idleTime);
            if (idleTime >= timeout) { // 60 minutes
                clearInterval(idleInterval);
                window.location.href = base_url + '/logout';
            }
        }
    }

    $('#user-menu').hover(function() {
        $('ul.dropdown').css('display', 'block').css('visibility', 'visible');
    }, function() {
        $('ul.dropdown').css('display', 'none').css('visibility', 'hidden');
    });

    $('#burgerimg').click(function(){
        $('#menu-overlay').css({'display': 'block', 'z-index': '10'});
        $('#crossimg').css('display', 'block');
        $('#burgerimg').hide();
        $('#header-menu').css('display', 'flex');

    });
    $('#crossimg').click(function(){
      hidemobnav();
      $('#user-menu').css('visibility', 'hidden');
    });
    $('#usermenulink').click(function(){
      $('#header-menu').removeAttr('style');
      $('#user-menu').css('visibility', 'visible');
      $('.dropdown').addClass('fromdropdown').removeClass('dropdown').css('display', 'flex');
      $('.fromdropdown').css('visibility', 'visible');
    });

    // confirmations
    $('.confirm').on('click', function() {
        var message = 'Are you sure?';
        if ( $("#current").text() == 'Reporting' ) {
            message = 'This will reset changes you have made to issues, including details added or issues merged/deleted';
        } else if ( $("#current").text() == 'Engagement' ) {
            message = 'This engagement will be permanently deleted';
        }
        return confirm(message);
    });

    // input validation
    //console.log($('.validate input[type=text]'));
    $(".validate").on('blur', function() {
        validate(this);
    });

    $("#toggler").click(function(){
        $(":checkbox").prop('checked', this.checked);
    });

    $('#gethelp').click(function() {
        $('#contact-popup, .overlay').css('display', 'block');
        $('#contact-popup')[0].scrollIntoView({ block: 'center' });
    });

    $('#getlogs').click(function() {
        var lines = [$('#message').val(),'','',''];
        $.ajaxSetup({ async: false });
        $.getJSON( "/getlogs", function( data ) {
            $.each( data, function( i, logline ) {
                lines.push( logline );
                console.log(logline);
            });
        });
        console.log(lines);
        console.log(lines.join('\n'));

        $('#message').val(lines.join('\n'));
        $.ajaxSetup({ async: true });
        return false;
    });

    $('#getupdates').click(function() {
        $('#updates-popup, .overlay').css('display', 'block');
        $('#updates-popup')[0].scrollIntoView({ block: 'center' });
        $('#updates-content').empty();
        var updatetypes = ['HaxHQ', 'Python', 'OS'];
        var i = 0;
        $('#updates-status').html('<p>Checking for ' + updatetypes[i] + ' updates...</p>');
        function check_updates(updatetype) {
            $.ajax({
                dataType: "html",
                url: '/get_updates/' + updatetype,
                success: function(data) {
                    if (data.startsWith('<!DOCTYPE html>')) {
                        window.location.href = base_url + '/login'
                    } else {
                        $(data).appendTo('#updates-content');
                        $('#update_' + updatetype).on('click', function() { install_update(updatetype); } );
                        i += 1;
                        if (i < updatetypes.length) {
                            $('#updates-status').html('<p>Checking for ' + updatetypes[i] + ' updates...</p>');
                            check_updates(updatetypes[i]);
                        } else {
                            $('#updates-status').empty();
                        }
                    }
                }
            });
        }
        check_updates(updatetypes[i]);
    });

    $('.close-popup').click(function() {
        $('#message').val('');
        $('.popup, .overlay').removeAttr('style');
    });

    if (( $("#current").text() == 'Reporting' && !$('#reportmenu').length )|| $("#current").text() == 'Library') {
        //CVSS calculator for edit issue form
        var c = new CVSS("cvss-calc-container", {
            onchange: function() {
                if ($('input:checked, #cvssjs').length == 8) {
                    $('input[type=submit], #cvssjs').val('Save');
                }
            },
            onsubmit: function() {
                var cvss3 = c.get();
                $('#cvss3').val(cvss3.score);
                $('#cvss3_vector').val(cvss3.vector);
                // submit also used as a cancel button
                if (cvss3.score != '?' && cvss3.score != '') {
                    update_severity(cvss3.score);
                }
                $('#cvss-calc-container, .overlay').css('display', 'none');
                return false;
            }
        });

        $('#cvss-calc').click(function(){
            if ($('#cvss3_vector').val()) {
                c.set($('#cvss3_vector').val());
            }
            $('#cvss-calc-container, .overlay').css('display', 'block');
        });

        // dont submit form if enter is pressed in the cvss field
        $('#cvss').keypress(function(event){
            if (event.which == '13') {
                event.preventDefault();
            }
        });
    }

    if ( $("#current").text() == 'Engagement' ) {
        // only run on engagement page
        let bgcolor = bodyStyles.getPropertyValue('--darker-card');
        let hovercolor = bodyStyles.getPropertyValue('--card-bg-color');
        let hoverred = bodyStyles.getPropertyValue('--hover-bg-red');

        $('.confirm').hover(
            function() { $(this).parents('.engagement').css('background-color', hoverred); },
            function() { $(this).parents('.engagement').css('background-color', bgcolor); }
        );

        $('.eng_link').hover(
            function() { $(this).parents('.engagement, #list_engagements').css('background-color', hovercolor); },
            function() { $(this).parents('.engagement, #list_engagements').css('background-color', bgcolor); }
        );

        $('#show_secondary').click(function() {
            $('.secondary_contact').removeClass('hidden');
            $('#show_secondary').hide();
        });

        $('#mk_dummy').click(function() {
            eng_type = $('#test_type').val()
            //if (typeof(eng_type) == 'undefined') {
            //    eng_type = 'audit';
            //}
            window.location.href = base_url + '/dummy_eng?eng_type=' + eng_type
        });

        $('#show_eng_form').click(function() {
            $('#eng_form').css('display', 'block').css('z-index','12')
                          .css('position', 'absolute').css('top', '100px').css('left', 'auto')
                          .css('width', '90%');
            $('#eng_buttons').css('display', 'none');
            $('.overlay').css('display', 'block');
            $('#content').css('margin-top', '20px');
        });

        $('#cancel_new_eng').click(function() {
            $('#eng_form, #content, #eng_buttons, .overlay').removeAttr('style');
            return false;
        });
            
        $('#show_eng_list').click(function() {
            if ($('#show_eng_list').text() == 'Show all engagements') {
                $('.engagement.hidden').removeClass('hidden');
                $('#show_eng_list').text('Hide old engagements');
                $('.engagement').css('display', 'flex');
            } else {
                $('.engagement').removeAttr('style');
                let num2hide = $('.engagement').length - 4;
                $('.engagement').slice(-num2hide).addClass('hidden');
                $('#show_eng_list').text('Show all engagements');
            }
            $('#list_engagements').css('background-color', '#798994');
            return false;
        });

    } else if ( $("#current").text() == 'Reporting' ) {
        // only run on Reporting page
        toggle_select_color('#exposure');
        toggle_select_color('#severity');
        //$('#affected_wrapper').width($('#vuln_affected').width()); 

        let bgcolor = bodyStyles.getPropertyValue('--darker-card');
        $('#reporting_burger').click(function() {
            $('#reportmenu').css('flex-direction', 'column').css('gap', '2em').css('align-items', 'center').css('max-width', '450px')
                            .css('position', 'absolute').css('top', '160px').css('left', '50%').css('transform', 'translate(-50%)')
                            .css('z-index', '100').css('background', bgcolor).css('border-radius', '5px')
                            .css('padding', '10px 5px 2em');
            $('.optblock, .overlay, #hide_repmenu').css('display', 'block');
            $('#reporting_burger').css('display', 'none');
        });

        $('#hide_repmenu').click(function() {
            $('#reportmenu, .optblock, .overlay, #hide_repmenu, #reporting_burger').removeAttr('style');
            return false;
        });

        $("#generate_report").click(function(e){
            e.preventDefault();
            window.location.href = base_url + '/generate_report?reportby=' + $('#current_reportby').text();
        });

        $("#reportby_link").click(function(){
            current_reportby = $('#current_reportby').text()
            reportby_changeto = $('#reportby_changeto').text()
            $('#current_reportby').text(reportby_changeto)
            $('#reportby_changeto').text(current_reportby)
            return false
        });

        $('#exposure').change(function(){ toggle_select_color('#exposure'); });
        $('#severity').change(function(){ toggle_select_color('#severity'); });

        $('#show_addhost').on('click', function() {
            $('#addhost').val('Save');
            if ($('#show_addhost').text() == 'Add host') {
                $('#vuln_affected').animate({scrollTop:8000000});   //arbitrary number exceeding any expected height
                $('#addissuehost_tr').removeClass('hidden');
                $('#show_addhost').text('Cancel');
                $('#ip0').focus();
            } else {
                $('#addissuehost_tr').addClass('hidden');
                $('#show_addhost').text('Add host');
            }
            return false;
        });
    
        $('#addhost').on('click', function() {
            // if adding host to an existing vuln
            if ( $('#vuln_title').length ) {
                $('.affected_host>input:not(:submit)').each(function(){
                    validate(this);
                });
                if ($(".invalid").exists()) {
                    return false;
                } else {
                    $('#addhostform').submit();
                }
            // if adding host as part of a new (manual) issue
            } else {
                xtra_host = $('.issue_hosts:first').clone();
                cancellink = $("<a>").attr("href", "#").attr("class", "hidehost").text('Cancel');
                cancellink.click(function(){ $(this).parents('.issue_hosts').remove() });
                xtra_host.children('#addhost').replaceWith(cancellink);
                xtra_host.children('#csrf_token').remove();

                n = $('.issue_hosts').length;
                xtra_host.children('input').each(function(){
                    idstr = $(this).attr('id').slice(0, -1) + n;
                    $(this).attr('id', idstr);
                    $(this).attr('name', idstr);
                    $(this).on('blur', function() {validate(this)});
                });
                xtra_host.children('label').each(function(){
                    forstr = $(this).attr('for') + n
                    $(this).attr('for', forstr)
                });
                xtra_host.insertAfter('.issue_hosts:last')
                return false
            }
        });

    
        $('.delete').hover(
            function() {
                $(this).parents('tr').css('background-color', '#ff6868');
            },
            function() { $(this).parents('tr').css('background-color', $('#vuln_affected').css('background-color')); }
        );

        //TODO add the hidden title input in forms.py
        let title = $('#vuln_title').text();
        input = $("<input>").attr("type", "hidden").attr("name", "title").val(title);
        $('#issueeditor').append(input);

        $('.libpending').click(function(){
            let classlist = $(this).attr('class').split(/\s+/);
            // this will break if the order in which the classes are assigned in jinja is changed
            let field = classlist[1]
            let type = classlist[2]
            $('.libpending.' + field).removeClass('current_text');
            if (type == 'old_scanner_text') {
                $(this).addClass('current_text');
                let container = $('.hidden.old_scanner_text.'+ field);
                $('#' + field).text(container.text());
            } else if (type == 'new_scanner_text') {
                $(this).addClass('current_text');
                let container = $('.hidden.new_scanner_text.'+ field);
                $('#' + field).text(container.text());
            } else {
                $(this).addClass('current_text');
                let container = $('.hidden.libtext.'+ field);
                $('#' + field).text(container.text());
            }
            return false;
        });
    
        $("#saveRep").click(function(){        
            $(".validate:not(:hidden)").each(function(){
                validate(this);
            });
            if ($(".invalid").exists()) {
                $('html, body').animate({ scrollTop: $($(".invalid")[0]).offset().top - 120 }, 0);
                return false;
            }
            input = $("<input>").attr("type", "hidden").attr("name", "cmd").val("saverep");
            $('#issueeditor').append(input);
            $("#issueeditor").submit();
        });
    
        $("#delRep").click(function(){  
            let input = $("<input>").attr("type", "hidden").attr("name", "cmd").val("delrep");
            $('#issueeditor').append(input);
            $("#issueeditor").submit();
        });
        $("#getMerge").click(function(){  
            window.location.href = base_url + '/get_merges/' + $('#iid').val();
        });
        $("#saveLib").click(function(){
            if (confirm_lib_update() == false) { return false; }
            //console.log('saving')
            $(".validate:not(:hidden)").each(function(){
                validate(this);
            });
            if ($(".invalid").exists()) {
                //console.log($(".invalid"))
                $('html, body').animate({ scrollTop: $($(".invalid")[0]).offset().top - 120 }, 0);
                return false;
            }
            let input = $("<input>").attr("type", "hidden").attr("name", "cmd").val("savelib");
            $('#issueeditor').append(input);
            $("#issueeditor").submit();
        });
        $("#saveRepLib").click(function(){
            if (confirm_lib_update() == false) { return false; }
            $(".validate:not(:hidden)").each(function(){
                validate(this);
            });
            if ($(".invalid").exists()) {
                $('html, body').animate({ scrollTop: $($(".invalid")[0]).offset().top - 120 }, 0);
                return false;
            }
            let input = $("<input>").attr("type", "hidden").attr("name", "cmd").val("savereplib");
            $('#issueeditor').append(input);
            $("#issueeditor").submit();
        });
    
        if ( $("#page_title").text() == 'Add finding' ) {
            // only run on Add issue page
            $( "#name" ).autocomplete({
                source: function(request, response) {
                    $.getJSON('get/titlelist', { 'term': $('#name').val(),
                                                 'type': $('#exposure').val()},
                                response);
                },

                minLength: 3,
                select: function( event, ui ) {
                    $.ajax({
                        dataType: "json",
                        url: base_url + "/get/lib_issue",
                        data: {title: ui.item.value},
                        success: function(data){ load_issue(data); },
                        global: false,
                    });
                }
            });

        } else if ( $('#issueeditor').length ) {
            // runs whenever editing issues - in library, while reporting or creating new
            $( "#discoverability" ).autocomplete({
                source: base_url + "/get/discoverabilitylist",
                minLength: 3
            });
            $( "#exploitability" ).autocomplete({
                source: base_url + "/get/exploitabilitylist",
                minLength: 3
            });
        }
    } else if ( $("#current").text() == 'Hacking' ) {
        // only run on Hacking pages
        let bgcolor = bodyStyles.getPropertyValue('--darker-card');
        let hovercolor = bodyStyles.getPropertyValue('--card-bg-color');
        $('#scantype').change(function(){ toggle_select_color('#scantype') });

        $('#xmlform').submit(function(e){
            e.preventDefault();
            upload_files();
            return false;
        });

        $('tr').hover(
            function() {
                let hid = $(this).attr('hid');
                if (typeof(hid) != 'undefined') {
                    $('tr[hid=' + hid + ']').css({'background-color': hovercolor}).click(function() {
                        window.location.href = base_url + '/hacking/' + hid;
                    });
                }
            },
            function() {
                let hid = $(this).attr('hid');
                if (typeof(hid) != 'undefined') {
                    $('tr[hid=' + hid + ']').removeAttr('style');
                }
            }
        );

        let hoverred = bodyStyles.getPropertyValue('--light-red');
        let textcolor = bodyStyles.getPropertyValue('--text-color');
        $('.delscan').hover(
            function() {
                bgcolor = $(this).parents('.impt_file').css('background-color', hoverred);
                $(this).css('color', textcolor);
                $(this).prev('.filename').css('color', textcolor);
            },
            function() {
                $(this).removeAttr('style');
                $(this).prev('.filename').removeAttr('style');
                $(this).parents('.impt_file').removeAttr('style');
            }
        );

        //$('.filename').hover(
        //    function() {
        //        bgcolor = $(this).parents('.impt_file').css('background-color');
        //        $(this).parents('.impt_file').css('background-color', '#fbf4e0');
        //    },
        //    function() { $(this).parents('.impt_file').css('background-color', bgcolor); }
        //);

        $( "#host" ).autocomplete({
            minLength: 0,
            source: function( request, response ) {
                var qdata = {'host': ''};
                $('.filter').each(function() {
                    if ($(this).val()) {
                        qdata[$(this).attr('id')] = $(this).val();
                    }
                });

                $.ajax({
                    url: base_url + "/get/hostlist",
                    data: qdata,
                    success: function(data){
                        response(data);
                    },
                    error: function(jqXHR, textStatus, errorThrown){
                        document.location.reload();
                    },
                  dataType: 'json'
                });
            }
        }).focus(function() {
            $(this).autocomplete("search");
        });
        $( "#port" ).autocomplete({
            minLength: 1,
            source: function( request, response ) {
                var qdata = {};
                $('.filter').each(function() {
                    if ($(this).val()) {
                        qdata[$(this).attr('id')] = $(this).val();
                    }
                });
                $.ajax({
                    url: base_url + "/get/portlist",
                    data: qdata,
                    success: function(data){
                        response(data);
                    },
                    error: function(jqXHR, textStatus, errorThrown){
                        document.location.reload();
                    },
                  dataType: 'json'
                });
            }
        });
        $( "#service" ).autocomplete({
            minLength: 1,
            source: function( request, response ) {
                var qdata = {};
                $('.filter').each(function() {
                    if ($(this).val()) {
                        qdata[$(this).attr('id')] = $(this).val();
                    }
                });
                $.ajax({
                    url: base_url + "/get/servicelist",
                    data: qdata,
                    success: function(data){
                        response(data);
                    },
                    error: function(jqXHR, textStatus, errorThrown){
                        document.location.reload();
                    },
                  dataType: 'json'
                });
            }
        });
        $( "#software" ).autocomplete({
            minLength: 1,
            source: function( request, response ) {
                var qdata = {};
                $('.filter').each(function() {
                    if ($(this).val()) {
                        qdata[$(this).attr('id')] = $(this).val();
                    }
                });
                $.ajax({
                    url: base_url + "/get/softwarelist",
                    data: qdata,
                    success: function(data){
                        response(data);
                    },
                    error: function(jqXHR, textStatus, errorThrown){
                        document.location.reload();
                    },
                  dataType: 'json'
                });
            }
        });
        $( "#findings" ).autocomplete({
            minLength: 1,
            source: function( request, response ) {
                var qdata = {};
                $('.filter').each(function() {
                    if ($(this).val()) {
                        qdata[$(this).attr('id')] = $(this).val();
                    }
                });
                $.ajax({
                    url: base_url + "/get/vulnlist",
                    data: qdata,
                    success: function(data){
                        response(data);
                    },
                    error: function(jqXHR, textStatus, errorThrown){
                        document.location.reload();
                    },
                  dataType: 'json'
                });
            }
        }).focus(function() {
            $(this).autocomplete("search");
        });

        $("#export-txt").click(function(e){
            e.preventDefault();
            window.location.href = base_url + '/export_iplist?host=' + $('#host').val()
                                                          + '&port=' + $('#port').val()
                                                          + '&service=' + $('#service').val()
                                                          + '&software=' + $('#software').val()
                                                          + '&findings=' + $('#findings').val();
            //var qdata = { 'csrf_token': $('#csrf_token').val() };
            //$('.filter').each(function() {
            //    qdata[$(this).attr('id')] = $(this).val();
            //});
            //$.post("/export_iplist", qdata);
        });
    } else if ( $("#current").text() == 'Stats' ) {
        // only run on Stats page
        $( "#title" ).autocomplete({
            source: function(request, response) {
                $.getJSON('get/stat_titlelist', { 'term': $('#title').val(),
                                                  'exposure': $('#exposure').val(),
                                                  'stat_from': $('#stat_from').val(),
                                                  'stat_to': $('#stat_to').val() },
                           response);
            },                 
            minLength: 3
        });
    } else if ( $("#current").text() == 'Library' ) {
        // only run on Library page
        empty_issue();
        toggle_select_color('#severity');
        toggle_select_color('#exposure');

        $('#exposure').change(function(){ toggle_select_color('#exposure'); });
        $('#severity').change(function(){ toggle_select_color('#severity'); });

        $( "#libsearchstr" ).autocomplete({
            source: function(request, response) {
                $.getJSON('get/titlelist', { 'term': $('#libsearchstr').val(),
                                             'type': $('#libsearchtype').val() },
                           response);
            },                 
            minLength: 3
        }).focus(function() {
            $(this).select();
        });

        $('#libnew').click(function(){
            $('textarea','#libview').val('');
            $('#altlib').empty();
            $('#formtitle').empty();
            $('#name').focus();
            return false;
        });

        $(".libtitle").click(function(e){
            $.ajax({
                dataType: "json",
                url: base_url + "/get/lib_issue",
                data: {title: $(e.target).children('span').last().text(),
                       exposure: $(e.target).children('span').first().text()},
                success: function(data){ load_issue(data); },
                global: false,
            });
        });

        if ($(".libtitle").length == 1) {
            $.ajax({
                dataType: "json",
                url: base_url + "/get/lib_issue",
                data: {title: $('.libtitle').first().children('span').last().text(),
                       exposure: $('.libtitle').first().children('span').first().text()},
                success: function(data){ load_issue(data); },
                global: false,
            });
        }
        
        $("#saveLib").click(function(){
            //console.log('saving')
            $(".validate:not(:hidden)").each(function(){
                validate(this);
            });
            if ($(".invalid").exists()) {
                //console.log($(".invalid"))
                $('html, body').animate({ scrollTop: $($(".invalid")[0]).offset().top - 120 }, 0);
                return false;
            }
            let input = $("<input>").attr("type", "hidden").attr("name", "cmd").val("savelib");
            $('#libeditor').append(input);
            $("#libeditor").submit();
        });

        $("#saveRepLib").click(function(){
            $(".validate:not(:hidden)").each(function(){
                validate(this);
            });
            if ($(".invalid").exists()) {
                $('html, body').animate({ scrollTop: $($(".invalid")[0]).offset().top - 120 }, 0);
                return false;
            }
            let input = $("<input>").attr("type", "hidden").attr("name", "cmd").val("savereplib");
            $('#libeditor').append(input);
            $("#libeditor").submit();
        });

        $('#delLib').click(function(){
            let input = $("<input>").attr("type", "hidden").attr("name", "cmd").val("dellib");
            $('#libeditor').append(input);
            $("#libeditor").submit();

        });

    } else if ( $("#page-title").text() == 'Administration' ) {
        // only run on administration & usersettings pages
        $('#adduser').click(function() {
            $.ajax({
                dataType: "HTML",
                url: base_url + "/manage_users",
                success: function(formhtml){
                    $('#user-popup-content').html(formhtml);
                },
                global: false,
            });
            $('#adduser-popup').css('display', 'block').css('z-index', 12);
            $('.overlay').css('display', 'block');
        });

        $('button#addlicense').click(function() {
            $('#message').val('We have grown 🎉 and need to purchase additional licenses!')
            $('#contact-popup, .overlay').css('display', 'block');
            $('#contact-popup')[0].scrollIntoView({ block: 'center' });
        });

        $('.edituser').click(function() {
            $('#adduser-popup').css('display', 'block').css('z-index', 12);
            $('.overlay').css('display', 'block');
            var uid = $(this).attr('uid');

            $.ajax({
                dataType: "HTML",
                url: base_url + "/manage_users",
                data: 'user_id=' + uid,
                success: function(formhtml){
                    $('#user-popup-content').html(formhtml);
                },
                global: false,
            });
            return false;
        });

        $('#init-ca').click(function() {
            return confirm('You are about to delete the existing CA and create a new one.\n\nOnce that is done you will be able to issue new client certificates and enable certificate authentication again.');
        });

        $('.close-popup').click(function() {
            // popup already cleared above, just reset form
            $('.uiclr').val('');
            $('#admin').prop('checked', false);
        });

    } else if ( $("#page-title").text() == 'User settings' ) {
        $('#getcert').click(function() {
            var confirm_text = '';
            if ($(this).val() == 'Issue') {
                confirm_text = 'A new certificate will be generated, please save it to a suitable location.\n\nIt will be encrypted with the certificate password you entered. You will need to provide this password when installing the certificate in your browser.'
            } else if ($(this).val() == 'Renew') {
                confirm_text += '\n\nThe old certificate will be revoked automatically the next time you use this new certificate to log in.'
            } else if ($(this).val() == 'Download') {
                confirm_text = 'You are about to download your more recent certificate, please save it to a suitable location.'
                confirm_text += '\n\nThe old certificate will be revoked automatically the next time you use this new certificate to log in.'
            } else {
                console.log($(this).val());
            }
            return confirm(confirm_text);
        });
        $('#certpassform').submit(function() {
            $('#getcert').attr('disabled', true).css('cursor', 'not-allowed');
            return true;
        });
    } else if ( $('#usetoken').length ) {
        // only run on usetoken page
        setTimeout(function() {
            window.location.href = base_url + '/usersettings';
        }, 1000);
    }

    $( ".datepicker" ).datepicker({ dateFormat:'d/m/yy', firstDay: 1 });

    $('.merge_on').change(function() {
        iid = this.name.split('_')[2];
        let this_status = $(this).prop('checked')
        $('.merge_on').prop('checked', false);
        $('.merge_on').parents('td').siblings().css('font-weight', '400');
        $('.merge').removeAttr('disabled');
        $(this).prop('checked', this_status);
        if (this_status) {
            $('.merge[name=' + iid + ']').prop('checked', false);
            $('.merge[name=' + iid + ']').attr('disabled', true);
            $(this).parents('td').siblings().css('font-weight', '700');
        } else {
            $(this).parents('td').siblings().css('font-weight', '400');
        }
        action = base_url + '/merge_issues/' + iid;
        $(this).parents('form').prop('action', action);
    });
    $('.merge').change(function() {
        if ($(this).prop('checked')) {
            $(this).parents('td').siblings().css('opacity', '0.6');
        } else {
            $(this).parents('td').siblings().css('opacity', '1');
        }
    });
});

function toggle_checkboxes(source) {
    inputs = document.getElementsByTagName('input');
    for(let input in inputs) {
        if (input.getAttribute('type') == 'checkbox') {
            input.checked = source.checked;
        }
    }
}

function validate(input) {
    if ((!$(input).prop('required') && !$(input).val()) || !$(input).is('visible') ) {
        console.log('ok')
        return true;
    }
    console.log($(input))
    let rgxp;
    let iprgxp = /^ip\d*/
    switch (input.name) {
        case 'user'             :
        case 'username'         :
        case 'contact1_email'   :
        case 'contact2_email'   : rgxp = /^[a-z0-9\._'-]{1,48}@[a-z0-9\.-]{4,48}$/i;        return rgx_test(rgxp, input); break;

        case 'nickname'         : rgxp = /^[0-9a-zA-Z \._'-]{1,20}$/;                       return rgx_test(rgxp, input); break;

        case 'org_name'         :
        case 'contact1_name'    :
        case 'contact1_role'    :
        case 'contact2_name'    :
        case 'contact2_role'    : rgxp = /^[a-zA-Z0-9.'_()":, -]{2,64}$/;                   return rgx_test(rgxp, input); break;

        case 'phone'            :
        case 'contact1_phone'   :
        case 'contact2_phone'   : rgxp = /^[0-9 +().-]{6,20}$/;                             return rgx_test(rgxp, input); break;

        case 'target_subnets'   : rgxp = /^[0-9.,\s\/]{7,}/;                                return rgx_test(rgxp, input); break;
        case 'target_urls'      : rgxp = /^[A-Za-z0-9._~:\/?#\[\]@!$&'()\*\+,;%=\s]{4,}$/;  return rgx_test(rgxp, input); break;

        case 'protocol0'        :
        case 'protocol1'        :
        case 'protocol2'        :
        case 'protocol3'        :
        case 'protocol4'        :
        case 'protocol'         : rgxp = /^[a-zA-Z]{2,12}$/;                                return rgx_test(rgxp, input); break;
        case 'port0'            :
        case 'port1'            :
        case 'port2'            :
        case 'port3'            :
        case 'port4'            :
        case 'port'             : rgxp = /^[0-9]{1,5}$/;                                    return rgx_test(rgxp, input); break;
        // try to get dynamic match to work
        // case /^ip\d*/.test(input.name) or similar
        case 'ip'               :
        case 'ip0'              :
        case 'ip1'              :
        case 'ip2'              :
        case 'ip3'              :
        case 'ip4'              :
        case 'ip5'              :
        case 'ip6'              :
        case 'ip7'              :
        case 'ip8'              :
        case 'ip9'              :
        case 'ip10'             : rgxp = /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/;            return rgx_test(rgxp, input); break;
        case 'name'             : rgxp = /^.{3,255}$/;                                      return rgx_test(rgxp, input); break;
        case 'severity'         : rgxp = /^[0-4]$/;                                         return rgx_test(rgxp, input); break;
        case 'description'      : rgxp = /^.{3,}/;                                          return rgx_test(rgxp, input); break;
        case 'remediation'      : rgxp = /^.{3,}/;                                          return rgx_test(rgxp, input); break;
        case 'compliance'       : rgxp = /^.{6,7}$/;                                        return rgx_test(rgxp, input); break;
        case 'hostname0'        :
        case 'hostname1'        :
        case 'hostname2'        :
        case 'hostname3'        :
        case 'hostname4'        :
        case 'hostname5'        :
        case 'hostname6'        :
        case 'hostname7'        :
        case 'hostname8'        :
        case 'hostname9'        :
        case 'hostname10'       : rgxp = /^[a-z][a-z0-9.-]{3,64}/;                          return rgx_test(rgxp, input); break;
    }
}

function rgx_test(rgx, input) {
    if (rgx.test(input.value)) {
        $(input).removeClass('invalid');
        $(input).addClass('valid');
        return true;
    } else {
        $(input).removeClass('valid');
        $(input).addClass('invalid');
        return false;
    }
}

function upload_files() {
    let files = $('#scanfile').prop('files');
    let imported = 0;
    $('#progress-panel, .overlay').css('display', 'block');
    $('#progress-panel').css('z-index', 100)
    $('#progress-panel')[0].scrollIntoView({ block: 'center' });
    for ( let i = 0; i < files.length; i++) {
        let fd = new FormData();
        fd.set( 'scanfile', files[i] );
        fd.set( 'csrf_token', $('#csrf_token').val() );
        fd.set( 'scantype', $('#scantype').val() );
        fd.set( 'filecount', files.length );
        let progressbar = "<p class='import-file-name'>" + files[i].name + "</p> <p class='upload-bar'><span id='uploaded-" + i + "' class='upload-percent'></span><span id='status-" + i + "' class='import-status'>uploading</span></p>";
        $('#progress-panel-grid').append(progressbar);

        $.ajax({
            xhr: function() {
                let xhr = new window.XMLHttpRequest();

                xhr.upload.addEventListener("progress", function(evt) {
                    if (evt.lengthComputable) {
                        let percentComplete = evt.loaded / evt.total;
                        percentComplete = parseInt(percentComplete * 100) + '%';
                        $('#uploaded-' + i).css('width', percentComplete);
                        if (percentComplete === '100%') {
                            $('#status-' + i).text('processing');
                        }
                    }
                }, false);

                return xhr;
            },
            url: base_url + '/upload_file',
            type: "POST",
            data: fd,
            processData: false,
            contentType: false,
            timeout: 240000, // 4 min
            success: function(data) {
                let result = jQuery.parseJSON(data);
                if (result.error == false) {
                    $('#status-' + i).text('done (' + result['import_time'] + 's)');
                } else {
                    //console.log('error: ' + files[i].name);
                    $('#status-' + i).text('error').addClass('red');
                }
                imported++;
                if (imported == files.length) {
                    window.location.href = base_url + '/hacking/main';
                }
            }
        });
    }
}
