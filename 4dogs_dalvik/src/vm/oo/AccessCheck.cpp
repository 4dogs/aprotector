/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/*
 * Check access to fields and methods.
 */
/*
 * 检查访问的字段和方法
 *
 */
#include "Dalvik.h"

/*
 * Return the #of initial characters that match.
 */
/*
 * 返回首字母匹配的状态(1,or 0)
 * 
 * 如果'str1'首字母为空则为0;如果'str1'与'str2'的首字母相同则为1，反之为0
 */
static int strcmpCount(const char* str1, const char* str2)
{
    int count = 0;

    while (true) {
        char ch = str1[count];
        if (ch == '\0' || ch != str2[count])
            return count;
        count++;
    }
}

/*
 * Returns "true" if the two classes are in the same runtime package.
 */
/*
 * 如果这两个类在同一个运行时包里面，则返回"true"
 *
 */
bool dvmInSamePackage(const ClassObject* class1, const ClassObject* class2)
{
    /* quick test for intra-class access */
    if (class1 == class2)
        return true;

    /* class loaders must match */
    if (class1->classLoader != class2->classLoader)
        return false;

    /*
     * Switch array classes to their element types.  Arrays receive the
     * class loader of the underlying element type.  The point of doing
     * this is to get the un-decorated class name, without all the
     * "[[L...;" stuff.
     */
    if (dvmIsArrayClass(class1))
        class1 = class1->elementClass;
    if (dvmIsArrayClass(class2))
        class2 = class2->elementClass;

    /* check again */
    if (class1 == class2)
        return true;

    /*
     * We have two classes with different names.  Compare them and see
     * if they match up through the final '/'.
     *
     *  Ljava/lang/Object; + Ljava/lang/Class;          --> true
     *  LFoo;              + LBar;                      --> true
     *  Ljava/lang/Object; + Ljava/io/File;             --> false
     *  Ljava/lang/Object; + Ljava/lang/reflect/Method; --> false
     */
    int commonLen;

    commonLen = strcmpCount(class1->descriptor, class2->descriptor);
    if (strchr(class1->descriptor + commonLen, '/') != NULL ||
        strchr(class2->descriptor + commonLen, '/') != NULL)
    {
        return false;
    }

    return true;
}

/*
 * Validate method/field access.
 */
/*
 * 验证方法和字段的访问
 *
 */
static bool checkAccess(const ClassObject* accessFrom,
    const ClassObject* accessTo, u4 accessFlags)
{
    /* quick accept for public access */
    if (accessFlags & ACC_PUBLIC)
        return true;

    /* quick accept for access from same class */
    if (accessFrom == accessTo)
        return true;

    /* quick reject for private access from another class */
    if (accessFlags & ACC_PRIVATE)
        return false;

    /*
     * Semi-quick test for protected access from a sub-class, which may or
     * may not be in the same package.
     */
    if (accessFlags & ACC_PROTECTED)
        if (dvmIsSubClass(accessFrom, accessTo))
            return true;

    /*
     * Allow protected and private access from other classes in the same
     * package.
     */
    return dvmInSamePackage(accessFrom, accessTo);
}

/*
 * Determine whether the "accessFrom" class is allowed to get at "clazz".
 *
 * It's allowed if "clazz" is public or is in the same package.  (Only
 * inner classes can be marked "private" or "protected", so we don't need
 * to check for it here.)
 */
/*
 *
 * 判断'accessFrom'类是否被允许去访问'clazz' 
 *
 * 如果'clazz'是public的或者在一个相同的包里它将被允许访问.(仅仅内部类能被标记为'private' or 'protected',因些我们在它这儿不需要去检查、判断)
 */
bool dvmCheckClassAccess(const ClassObject* accessFrom,
    const ClassObject* clazz)
{
    if (dvmIsPublicClass(clazz))
        return true;
    return dvmInSamePackage(accessFrom, clazz);
}

/*
 * Determine whether the "accessFrom" class is allowed to get at "method".
 */
/*
 *
 * 判断'accessFrom'类是否被允许去访问'method'
 *
 */
bool dvmCheckMethodAccess(const ClassObject* accessFrom, const Method* method)
{
    return checkAccess(accessFrom, method->clazz, method->accessFlags);
}

/*
 * Determine whether the "accessFrom" class is allowed to get at "field".
 */
/*
 *
 * 判断'accessFrom'类是否被允许去访问'field'
 *
 */
bool dvmCheckFieldAccess(const ClassObject* accessFrom, const Field* field)
{
    //ALOGI("CHECK ACCESS from '%s' to field '%s' (in %s) flags=%#x",
    //    accessFrom->descriptor, field->name,
    //    field->clazz->descriptor, field->accessFlags);
    return checkAccess(accessFrom, field->clazz, field->accessFlags);
}
